package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
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
	cli cloudwatchlogsiface.CloudWatchLogsAPI

	logger *log.Logger

	helpMode    bool
	versionMode bool
	debugMode   bool

	version string

	startInput, endInput string
	startTime, endTime   time.Time
	limit                int64
	logGroupInput        string
	queryString          string

	before time.Duration
	after  time.Duration

	_ json.Marshaler = (*logEvent)(nil)
)

func (e *logEvent) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"message":   e.Message,
		"timestamp": e.Timestamp.UTC().Format(cloudwatchTimestampStrFormat),
	})
}

func init() {
	flag.Usage = func() {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", usage)
	}
	flag.BoolVar(&helpMode, "h", false, "help")
	flag.BoolVar(&versionMode, "v", false, "version")
	flag.BoolVar(&debugMode, "d", false, "debug")
	flag.StringVar(&startInput, "s", "", "query start time; RFC3339 formatted")
	flag.StringVar(&endInput, "e", "", "query emd time; RFC3339 formatted")
	flag.Int64Var(&limit, "l", 0, "limit")
	flag.StringVar(&logGroupInput, "g", "", "log group name(s)")
	flag.StringVar(&queryString, "q", "", "query string")
	flag.DurationVar(&before, "b", 0, "a parameter to search log events in a log stream")
	flag.DurationVar(&after, "a", 0, "a parameter to search log events in a log stream")
	flag.Parse()

	if len(os.Args) < 2 {
		helpMode = true
	}

	if debugMode {
		logger = log.New(os.Stderr, "", log.Ldate)
	}
}

func main() {
	if helpMode {
		printHelp()
		os.Exit(0)
	}

	if versionMode {
		fmt.Printf(version)
		os.Exit(0)
	}

	cli = cloudwatchlogs.New(session.Must(session.NewSession()))

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer func() { done <- struct{}{} }()
		if err := handleQueryCommand(ctx); err != nil {
			printErrorWithUsage(err)
			os.Exit(1)
		}
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)

	select {
	case <-sigs:
		printDebug("canceled")
	case <-done:
		printDebug("done")
	}

	cancel()
}

func handleQueryCommand(ctx context.Context) error {
	now := time.Now()

	if startInput != "" {
		t, err := time.Parse(time.RFC3339, startInput)
		if err != nil {
			return fmt.Errorf("invalid start time format: %s", err)
		}
		startTime = t
	}

	if startTime.IsZero() {
		startTime = now.Add(-time.Hour)
	}

	if endInput != "" {
		t, err := time.Parse(time.RFC3339, endInput)
		if err != nil {
			return fmt.Errorf("invalid end time format: %s", err)
		}
		endTime = t
	}

	if endTime.IsZero() {
		endTime = now
	}

	if !endTime.After(startTime) {
		return fmt.Errorf("end time should be after start time")
	}

	if limit == 0 {
		limit = 1000
	}

	if logGroupInput == "" {
		return fmt.Errorf("log grou name(s) should be spedified")
	}
	var logGroupNames []*string
	for _, lg := range strings.Split(logGroupInput, ",") {
		lg := strings.TrimSpace(lg)
		logGroupNames = append(logGroupNames, &lg)
	}

	if queryString == "" {
		return fmt.Errorf("query string should be specified")
	}

	startQueryInput := cloudwatchlogs.StartQueryInput{
		QueryString:   &queryString,
		LogGroupNames: logGroupNames,
		StartTime:     aws.Int64(startTime.Unix()),
		EndTime:       aws.Int64(endTime.Unix()),
		Limit:         &limit,
	}

	startQueryOutput, err := cli.StartQuery(&startQueryInput)
	if err != nil {
		return fmt.Errorf("failed StartQuery request: %w", err)
	}

	const tickerDuration = 3 * time.Second
	ticker := time.NewTicker(tickerDuration)
	defer func() {
		ticker.Stop()
	}()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}

		getQueryResultInput := cloudwatchlogs.GetQueryResultsInput{
			QueryId: startQueryOutput.QueryId,
		}
		getQueryResultOutput, err := cli.GetQueryResults(&getQueryResultInput)
		if err != nil {
			return fmt.Errorf("failed GetQueryResult request: %w", err)
		}

		if *getQueryResultOutput.Status != "Complete" {
			printDebug("Query#%s is %s; will retry in %s...", *startQueryOutput.QueryId, *getQueryResultOutput.Status, tickerDuration)
			continue
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

		if canGetSurroundings && (before > 0 || after > 0) {
			attachSurroundings(ctx, rs)
		}

		enc := json.NewEncoder(os.Stdout)
		if err := enc.Encode(rs); err != nil {
			return fmt.Errorf("failed to encode query result: %w", err)
		}
		return nil
	}
}

func attachSurroundings(ctx context.Context, rs []*queryResult) {
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
		start := timestamp.Add(-before)
		end := timestamp.Add(after)

		logEvents, err := getLogEvents(ctx, logGroup, logStreamField, start, end)
		if err != nil {
			printDebug("failed to get log events from %s:%s between %s and %s", logGroup, logStreamField, start, end)
			continue
		}

		r.Surroundings = logEvents
	}
}

func getLogEvents(ctx context.Context, group, stream string, start time.Time, end time.Time) ([]logEvent, error) {
	startTime := start.UnixNano()/int64(time.Millisecond) - before.Milliseconds()
	endTime := end.UnixNano()/int64(time.Millisecond) + after.Milliseconds()

	input := &cloudwatchlogs.GetLogEventsInput{
		LogGroupName:  &group,
		LogStreamName: &stream,
		StartTime:     &startTime,
		EndTime:       &endTime,
	}

	var events []logEvent
	if err := cli.GetLogEventsPagesWithContext(ctx, input, func(output *cloudwatchlogs.GetLogEventsOutput, b bool) bool {
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

func printErrorWithUsage(err error) {
	_, _ = fmt.Fprintf(os.Stderr, "%s\n%s\n", err, usage)
}

func printDebug(fmt string, v ...interface{}) {
	if logger != nil {
		logger.Printf(fmt, v...)
	}
}
