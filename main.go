package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go/service/cloudwatchlogs/cloudwatchlogsiface"
)

type (
	queryResult struct {
		Fields       map[string]string `json:"fields"`
		Surroundings []logEvent        `json:"surroundings"`
	}

	logEvent struct {
		Message   string
		Timestamp time.Time
	}
)

var (
	cli cloudwatchlogsiface.CloudWatchLogsAPI

	logger *log.Logger

	help    bool
	verbose bool

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

const cloudwatchTimestampStrFormat = "2006-01-02 15:04:05.999"

func printUsage() {
	fmt.Printf("cwq [-h] [-v] [-s <start time>] [-e <end time>] [-l <limit>] [-b <duration before>] [-a <duration after>] -g <log-group(s)> <query>")
}

func debug(fmt string, v ...interface{}) {
	if logger != nil {
		logger.Printf(fmt, v...)
	}
}

func init() {
	flag.BoolVar(&help, "h", false, "help")
	flag.BoolVar(&verbose, "v", false, "verbose")
	flag.StringVar(&startInput, "s", "", "query start time; RFC3339 formatted")
	flag.StringVar(&endInput, "e", "", "query emd time; RFC3339 formatted")
	flag.Int64Var(&limit, "l", 0, "limit")
	flag.StringVar(&logGroupInput, "g", "", "log group name(s)")
	flag.DurationVar(&before, "b", 0, "a parameter to search log events in a log stream")
	flag.DurationVar(&after, "a", 0, "a parameter to search log events in a log stream")
	flag.Parse()
	queryString = flag.Arg(0)

	logger = log.New(os.Stderr, "", log.Ldate)
}

func main() {
	args := flag.Args()
	if help || len(args) < 1 {
		printUsage()
		os.Exit(0)
	}

	cli = cloudwatchlogs.New(session.Must(session.NewSession()))

	if err := handleQueryCommand(args); err != nil {
		fmt.Printf("execution error: %s\n", err)
		os.Exit(1)
	}
}

func handleQueryCommand(args []string) error {
	now := time.Now()

	if startInput != "" {
		t, err := time.Parse(time.RFC3339, startInput)
		if err != nil {
			return fmt.Errorf("invalid -start time format: %s", err)
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

	if startTime.After(endTime) {
		return fmt.Errorf("start time must be equal or before end time")
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
		return fmt.Errorf("query string must not be empty")
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
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	ticker := time.NewTicker(tickerDuration)
	defer func() {
		ticker.Stop()
		cancel()
	}()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout getting query result")
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
			debug("Query#%s is %s; will retry in %s...", *startQueryOutput.QueryId, *getQueryResultOutput.Status, tickerDuration)
			continue
		}

		rs := make([]*queryResult, len(getQueryResultOutput.Results))

		var canGetSurroundings bool
		for i, fields := range getQueryResultOutput.Results {
			m := make(map[string]string)

			var hasTimestampField, hasLogField, hasLogStreamField bool
			for _, field := range fields {
				switch *field.Field {
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
				Fields: m,
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
		log, ok := r.Fields["@log"]
		if !ok {
			debug("@log field doesn't exist unexpectedly")
			continue
		}
		logGroup, ok := extractLogGroupNameFromLogField(log)
		if !ok {
			debug("@log field might be unexpected format: %s", log)
			continue
		}

		logStream, ok := r.Fields["@logStream"]
		if !ok {
			debug("@logStream field doesn't exist unexpectedly")
			continue
		}

		timestampStr, ok := r.Fields["@timestamp"]
		if !ok {
			debug("@timestamp field doesn't exist unexpectedly")
			continue
		}
		timestamp, ok := extractTimeFromTimestampField(timestampStr)
		if !ok {
			debug("@timestamp field might be unexpected format: %s", timestamp)
			continue
		}
		start := timestamp.Add(-before)
		end := timestamp.Add(after)

		logEvents, err := getLogEvents(ctx, logGroup, logStream, start, end)
		if err != nil {
			debug("failed to get log events from %s:%s between %s and %s", logGroup, logStream, start, end)
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
