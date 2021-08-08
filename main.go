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
)

type (
	queryResult struct {
		Fields map[string]string `json:"fields"`
	}
)

var (
	logger *log.Logger

	help    bool
	verbose bool

	startInput, endInput string
	startTime, endTime   time.Time
	queryString          string
	logGroupInput        string
)

func printUsage() {
	fmt.Printf("cwq [-h] [-v] [-s <start-time>] [-e <end-time>] -g <log groups> <query>")
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
	flag.StringVar(&logGroupInput, "g", "", "log group name(s)")
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
		Limit:         aws.Int64(10000),
	}

	cli := cloudwatchlogs.New(session.Must(session.NewSession()))

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

		switch *getQueryResultOutput.Status {
		case "Complete":
			rs := make([]queryResult, len(getQueryResultOutput.Results))
			for i, fields := range getQueryResultOutput.Results {
				m := make(map[string]string)
				for _, field := range fields {
					m[*field.Field] = *field.Value
				}
				rs[i] = queryResult{
					Fields: m,
				}
			}

			enc := json.NewEncoder(os.Stdout)
			if err := enc.Encode(rs); err != nil {
				return fmt.Errorf("failed to encode query result: %w", err)
			}
			return nil
		default:
		}

		debug("Query#%s is "+
			" %s; will retry in %s...", *startQueryOutput.QueryId, *getQueryResultOutput.Status, tickerDuration)
	}
}
