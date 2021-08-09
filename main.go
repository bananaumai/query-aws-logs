package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs/cloudwatchlogsiface"
)

const usage = `Usage: query-aws-logs [-h] [-v] [-d] [-s <start>] [-e <end>] [-l <limit>] [-b <before>] [-a <after>] -g <group(s)> -q <query>

Available options are listed below:

Required options:
  -q	Query string. Consolidating with CloudWatch Logs Insights query syntax.
  -g	Log group name(s). If you want to specify multiple log groups, delimit each log group by ","(comma).
    	See https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html for detailed syntax.
    	Note "limit" won't work instead use -l options to limit the number of the logs events to be returned.

Non-required options:
  -h	Help flag. If specified, the command usage will be displayed. False by default.
  -v    Version flag. If specified, version information is displayed. False by default.
  -d    Debug flag. If specified, the printDebug print will be output in stderr. False by default.
  -s	Start time in RFC3339 format. The logs after this timestamp will be queried. One hour before current time by default.
  -e	End time in RFC3339 format. The logs before this time stamp will be queried. Current time by default.
  -l    Limit of the number of returned logs events which match against query. 1000 by default
  -b    Before. A time duration parameter specifying how long before the query matched log event timestamp to be used to search the logs around.
  -a	After. A time duration parameter specifying how long after the query matched log event timestamp to be used to search the logs around.

You are supposed to specify -b and -a option by the duration string: 1s => 1 second, 1ms => 1 milli-sec.

Query results will be JSON array whose element consist of two fields "result" and "surroundings".
The "result" field simply reflects the result of the query string that you specify.
The "surroundings" field reflects the logs around the logs in "result" field in the same log stream.`

const helpMsg = `query-aws-logs - Query AWS CloudWatch Logs

query-aws-logs is a wrapper tool for CloudWatch Logs Insights Query API that help your CloudWatch Logs investigation.
You can retrieve the CloudWatch Logs Insights Query result in JSON format more easily than using aws-cli.
Additionally, you can retrieve the logs around the logs which exactly match query.
This would be helpful when you try investigating the logs in CloudWatch Logs.

%s

Note1 - how to get "surroundings" fields: 

  you may need to follow the following conventions to get "surroundings" field properly;

  * In -q(query) option, make sure that "@timestamp", "@log", "@logStream" fields are output.
  * Specify either or both of -b(before) and -a(after) options.

Note2 - specify AWS region, profile, credentials by your env vars

  query-aws-logs doesn't provide the way to specify AWS related parameters.
  Use AWS standard env vars to specify them;
  i.e. AWS_DEFAULT_REGION, AWS_PROFILE, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY 

Example1 - retrieving logs:

  $ query-aws-logs -g my-log-group -q 'fields @timestamp, @message'

  This command would output the JSON looking like below:

  [
    {
      "result": {
        "@message": "[ERROR] an error log",
        "@timestamp": "2021-08-13 00:01:05.923",
      }
    },
    ...
  ]

Example2 - retrieving logs that contain "ERROR" string with surrounding logs:

  $ query-aws-logs -g my-log-group -q 'fields @timestamp,@message,@log,@logStream | @message like "ERROR"' -b 10ms 

  This command would output the JSON looking like below:

  [
    {
      "result": {
        "@log": "7825xxxxxxxx:my-log-group",
        "@logStream": "my/log/stream/2bs4b5b05b0a3ebd1201871s32486f0z",
        "@message": "[ERROR] an error log",
        "@timestamp": "2021-08-13 00:01:05.923",
      },
      "surroundings": [
        {
          "message": "[INFO] some logs in 10 ms before a log event that has matched against the query"
          "timestamp": "2021-08-13 00:01:05.915"
        },
        ...
      ]
    },
    ...
  ]`

type (
	queryHandler struct {
		queryID        string
		queryCompleted bool

		queryString        string
		logGroupNames      []*string
		startTime, endTime time.Time
		limit              int64
		before             time.Duration
		after              time.Duration

		once  sync.Once
		mutex sync.Mutex
		enc   *json.Encoder

		cli cloudwatchlogsiface.CloudWatchLogsAPI
	}

	queryHandlerConfig struct {
		queryString, logGroupNames, startTime, endTime string
		limit                                          int64
		before, after                                  time.Duration
		enc                                            *json.Encoder
	}

	queryResult struct {
		Result       map[string]string `json:"result"`
		Surroundings []logEvent        `json:"surroundings,omitempty"`
	}

	logEvent struct {
		Message   string
		Timestamp time.Time
	}
)

const cloudwatchTimestampStrFormat = "2006-01-02 15:04:05.999"

var (
	version string

	logger *log.Logger

	helpMode    bool
	versionMode bool
	debugMode   bool
	prettyMode  bool

	_ json.Marshaler = (*logEvent)(nil)
)

func (e *logEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"message":   e.Message,
		"timestamp": e.Timestamp.UTC().Format(cloudwatchTimestampStrFormat),
	})
}

func newQueryHandler(cfg queryHandlerConfig) (*queryHandler, error) {
	h := &queryHandler{}

	sess, err := session.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create new AWS Session: %w", err)
	}
	h.cli = cloudwatchlogs.New(sess)

	now := time.Now()

	if cfg.startTime != "" {
		t, err := time.Parse(time.RFC3339, cfg.startTime)
		if err != nil {
			return nil, fmt.Errorf("invalid start time format: %s", err)
		}
		h.startTime = t
	}
	if h.startTime.IsZero() {
		h.startTime = now.Add(-time.Hour)
	}

	if cfg.endTime != "" {
		t, err := time.Parse(time.RFC3339, cfg.endTime)
		if err != nil {
			return nil, fmt.Errorf("invalid end time format: %s", err)
		}
		h.endTime = t
	}
	if h.endTime.IsZero() {
		h.endTime = now
	}

	if !h.endTime.After(h.startTime) {
		return nil, fmt.Errorf("end time should be after start time")
	}

	h.limit = cfg.limit
	if h.limit == 0 {
		h.limit = 1000
	}

	h.before = cfg.before
	h.after = cfg.after

	if cfg.logGroupNames == "" {
		return nil, fmt.Errorf("log grou name(s) should be spedified")
	}
	for _, lg := range strings.Split(cfg.logGroupNames, ",") {
		lg := strings.TrimSpace(lg)
		h.logGroupNames = append(h.logGroupNames, &lg)
	}

	if cfg.queryString == "" {
		return nil, fmt.Errorf("query string should be specified")
	}
	h.queryString = cfg.queryString

	h.enc = cfg.enc

	return h, nil
}

func (h *queryHandler) handle(ctx context.Context) error {
	printDebug("calling StartQuery API...")
	startQueryInput := cloudwatchlogs.StartQueryInput{
		QueryString:   &h.queryString,
		LogGroupNames: h.logGroupNames,
		StartTime:     aws.Int64(h.startTime.Unix()),
		EndTime:       aws.Int64(h.endTime.Unix()),
		Limit:         &h.limit,
	}
	startQueryOutput, err := h.cli.StartQuery(&startQueryInput)
	if err != nil {
		return fmt.Errorf("failed StartQuery request: %w", err)
	}

	const tickerDuration = 3 * time.Second
	ticker := time.NewTicker(tickerDuration)
	defer func() {
		ticker.Stop()
	}()

	h.queryID = *startQueryOutput.QueryId
	printDebug("Query#%s is acquired", h.queryID)

	var getQueryResultOutput *cloudwatchlogs.GetQueryResultsOutput
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		printDebug("calling GetQueryResults API with Query#%s...", h.queryID)
		getQueryResultInput := cloudwatchlogs.GetQueryResultsInput{
			QueryId: &h.queryID,
		}
		getQueryResultOutput, err = h.cli.GetQueryResults(&getQueryResultInput)
		if err != nil {
			return fmt.Errorf("failed GetQueryResult request: %w", err)
		}

		if *getQueryResultOutput.Status != "Complete" {
			printDebug("Query#%s status is still %s; will retry in %s...", h.queryID, *getQueryResultOutput.Status, tickerDuration)
			continue
		}

		h.queryCompleted = true
		printDebug("Query#%s is completed: { bytesScanned: %f, recordsScanned: %f, recordsMatched: %f } ",
			h.queryID, *getQueryResultOutput.Statistics.BytesScanned, *getQueryResultOutput.Statistics.RecordsScanned, *getQueryResultOutput.Statistics.RecordsMatched)
		break
	}

	rs := make([]*queryResult, len(getQueryResultOutput.Results))
	var canGetSurroundings bool
	for i, fields := range getQueryResultOutput.Results {
		m := make(map[string]string)

		var hasTimestampField, hasLogField, hasLogStreamField bool
		for _, field := range fields {
			switch *field.Field {
			case "@ptr":
				// Note: @ptr fields are omitted
				continue
			case "@timestamp":
				hasTimestampField = true
			case "@log":
				hasLogField = true
			case "@logStream":
				hasLogStreamField = true
			}

			m[*field.Field] = *field.Value
		}

		if hasTimestampField && hasLogField && hasLogStreamField {
			canGetSurroundings = true
		}

		rs[i] = &queryResult{
			Result: m,
		}
	}

	if canGetSurroundings && (h.before > 0 || h.after > 0) {
		printDebug("attaching surrounding logs...")
		h.attachSurroundings(ctx, rs)
	}

	if err := h.enc.Encode(rs); err != nil {
		return fmt.Errorf("failed to encode query result: %w", err)
	}
	return nil
}

func (h *queryHandler) attachSurroundings(ctx context.Context, rs []*queryResult) {
	for _, r := range rs {
		logField, ok := r.Result["@log"]
		if !ok {
			printDebug("@log field doesn't exist unexpectedly")
			continue
		}
		logGroup, ok := extractLogGroupNameFromLogField(logField)
		if !ok {
			printDebug("@log field might be unexpected format: %s", logField)
			continue
		}

		logStreamField, ok := r.Result["@logStream"]
		if !ok {
			printDebug("@logStream field doesn't exist unexpectedly")
			continue
		}

		timestampField, ok := r.Result["@timestamp"]
		if !ok {
			printDebug("@timestamp field doesn't exist unexpectedly")
			continue
		}
		timestamp, ok := extractTimeFromTimestampField(timestampField)
		if !ok {
			printDebug("@timestamp field might be unexpected format: %s", timestamp)
			continue
		}
		start := timestamp.Add(-h.before)
		end := timestamp.Add(h.after)

		logEvents, err := h.getLogEvents(ctx, logGroup, logStreamField, start, end)
		if err != nil {
			printDebug("failed to get log events from %s:%s between %s and %s", logGroup, logStreamField, start, end)
			continue
		}

		r.Surroundings = logEvents
	}
}

func (h *queryHandler) getLogEvents(ctx context.Context, group, stream string, start time.Time, end time.Time) ([]logEvent, error) {
	startTime := start.UnixNano()/int64(time.Millisecond) - h.before.Milliseconds()
	endTime := end.UnixNano()/int64(time.Millisecond) + h.after.Milliseconds()

	input := &cloudwatchlogs.GetLogEventsInput{
		LogGroupName:  &group,
		LogStreamName: &stream,
		StartTime:     &startTime,
		EndTime:       &endTime,
	}

	printDebug("retrieving logs in %s::%s (%s-%s) from GetLogEvents API", group, stream, start.UTC().Format(cloudwatchTimestampStrFormat), end.UTC().Format(cloudwatchTimestampStrFormat))
	var events []logEvent
	if err := h.cli.GetLogEventsPagesWithContext(ctx, input, func(output *cloudwatchlogs.GetLogEventsOutput, b bool) bool {
		if output == nil || len(output.Events) == 0 {
			return false
		}
		for _, ev := range output.Events {
			// Note: `ingestionTime` is omitted
			events = append(events, logEvent{
				Timestamp: epochMilliToTime(*ev.Timestamp),
				Message:   *ev.Message,
			})
		}
		return true
	}); err != nil {
		return nil, err
	}

	return events, nil
}

func (h *queryHandler) cancel(timeout time.Duration) error {
	if h.queryID == "" || h.queryCompleted {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		printDebug("calling StopQuery API with Query#%s...", h.queryID)
		output, err := h.cli.StopQuery(&cloudwatchlogs.StopQueryInput{QueryId: &h.queryID})
		if err != nil {
			done <- fmt.Errorf("StopQuery API call has failed: %w", err)
			return
		}
		if output.Success != nil && !*output.Success {
			done <- errors.New("StopQuery API call didn't succeed")
			return
		}
		printDebug("Query#%s has successfully been stopped", h.queryID)
		done <- nil
	}()

	select {
	case <-ctx.Done():
		return errors.New("StopQuery API call has timed out")
	case err := <-done:
		return err
	}
}

func main() {
	cfg := queryHandlerConfig{}

	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", usage)
	}
	flag.BoolVar(&helpMode, "h", false, "help")
	flag.BoolVar(&versionMode, "v", false, "version")
	flag.BoolVar(&debugMode, "d", false, "debug")
	flag.BoolVar(&prettyMode, "p", false, "pretty print")
	flag.StringVar(&cfg.startTime, "s", "", "query start time; RFC3339 formatted")
	flag.StringVar(&cfg.endTime, "e", "", "query emd time; RFC3339 formatted")
	flag.Int64Var(&cfg.limit, "l", 0, "limit")
	flag.StringVar(&cfg.logGroupNames, "g", "", "log group name(s)")
	flag.StringVar(&cfg.queryString, "q", "", "query string")
	flag.DurationVar(&cfg.before, "b", 0, "a parameter to search log events in a log stream")
	flag.DurationVar(&cfg.after, "a", 0, "a parameter to search log events in a log stream")
	flag.Parse()

	if len(os.Args) < 2 {
		helpMode = true
	}

	if helpMode {
		printHelp()
		os.Exit(0)
	}

	if versionMode {
		fmt.Printf(version)
		os.Exit(0)
	}

	if debugMode {
		logger = log.New(os.Stderr, "", log.Ldate)
	}

	enc := json.NewEncoder(os.Stdout)
	if prettyMode {
		enc.SetIndent("", "  ")
	}
	cfg.enc = enc

	handler, err := newQueryHandler(cfg)
	if err != nil {
		printErrorWithUsage(err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{}, 1)
	go func() {
		defer func() { done <- struct{}{} }()
		if err := handler.handle(ctx); err != nil {
			printError(err)
			os.Exit(1)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)

	select {
	case <-sigs:
		cancel()
		if err := handler.cancel(10 * time.Second); err != nil {
			printError(err)
			os.Exit(1)
		}
		printDebug("operation has been canceled")
	case <-done:
		printDebug("operation has been completed")
	}
}

func extractTimeFromTimestampField(timestampField string) (time.Time, bool) {
	timestamp, err := time.Parse(cloudwatchTimestampStrFormat, timestampField)
	return timestamp, err == nil
}

// extractLogGroupNameFromLogField extract log group name from @log field in the Cloud Watch Logs Insight query result.
//
// It is assumed to be in the following format:
//
// {AWS_ACCOUNT_ID}:{LOG_GROUP_NAME}
func extractLogGroupNameFromLogField(logField string) (string, bool) {
	parts := strings.Split(logField, ":")
	if len(parts) < 2 {
		return "", false
	}
	return parts[1], true
}

func epochMilliToTime(epoch int64) time.Time {
	sec := epoch / 1000
	msec := epoch - sec*1000
	nsec := msec * int64(time.Millisecond)
	return time.Unix(sec, nsec)
}

func printHelp() {
	_, _ = fmt.Fprintf(os.Stdout, helpMsg, usage)
}

func printError(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "%s\n", err)
}

func printErrorWithUsage(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "%s\n%s\n", err, usage)
}

func printDebug(fmt string, v ...interface{}) {
	if logger != nil {
		logger.Printf(fmt, v...)
	}
}
