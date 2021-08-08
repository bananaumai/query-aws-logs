# qal - Query AWS CloudWatch Logs

qal is a wrapper tool for [CloudWatch Logs Insights Query API](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/AnalyzingLogData.html) that help your CloudWatch Logs investigation.
You can retrieve the CloudWatch Logs Insights Query result in JSON format more easily than using aws-cli.
Additionally, you can retrieve the logs around the logs which exactly match query.
This would be helpful when you try investigating the logs in CloudWatch Logs.

The query result will be returned JSON array which is easily manipulated by the JSON tools like `jq`.

## Usage

```
$ qal [-h] [-v] [-s start] [-e end] [-l limit] [-b before] [-a after] -g group(s) -q query
```

### Required options:

* -q	Query string. Consolidating with CloudWatch Logs Insights query syntax.
* -g	Log group name(s). If you want to specify multiple log groups, delimit each log group by ","(comma). 

See [official documentation](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CWL_QuerySyntax.html) for the detailed syntax.
But, note "limit" won't work instead use -l options to limit the number of the logs events to be returned.

### Non-required options:


* -h	Help flag. If specified, the command usage will be displayed. False by default.
* -v    Verbose flag. If specified, the debug print will be output in stderr. False by default.
* -s	Start time in RFC3339 format. The logs after this timestamp will be queried. One hour before current time by default.
* -e	End time in RFC3339 format. The logs before this time stamp will be queried. Current time by default.
* -l    Limit of the number of returned logs events which match against query. 1000 by default
* -b    Before. A time duration parameter specifying how long before the query matched log event timestamp to be used to search the logs around.
* -a	After. A time duration parameter specifying how long after the query matched log event timestamp to be used to search the logs around.

## Motivation

Actually it's possible to acquire exactly same results, getting CloudWatch Logs Insights query result and
seeing the related logs from CloudWatch Logs stream, by using `aws-cli` and/or AWS Console.

But it is a little cumbersome to perform this.

For example, let's imagine the situation, if you want to get "ERROR" logs from a log group
and you want to see the some amount log lines recorded just before the each "ERROR" logs.

If you use aws-cli for this purpose, you may need to perform the following steps:

```
$ aws logs start-query --query-string 'fields @timestamp, @message | filter @message like "ERROR"' --start-time ... --end-time ... --log-group ...

# query id will be returned

$ aws logs get-query-result --query-id ...

# try until the query execution status would be "Complete"
# then parse the results json.
# for each event in the returned json, perform following command

$ aws logs get-log-events ...
```

## Notes

### How to get "surroundings" fields:

you may need to follow the following conventions to get "surroundings" field properly;

* In -q(query) option, make sure that "@timestamp", "@log", "@logStream" fields are output.
* Specify either or both of -b(before) and -a(after) options.

### Specify AWS region, profile, credentials by your env vars

qal doesn't provide the way to specify AWS related parameters.
Use AWS standard env vars to specify them;
i.e. AWS_DEFAULT_REGION, AWS_PROFILE, AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY

## Examples

### Example1 - retrieving logs:

```
$ qal -g my-log-group -q 'fields @timestamp, @message'
```

This command would output the JSON looking like below:

```
[
  {
    "result": {
      "@message": "[ERROR] an error log",
      "@timestamp": "2021-08-13 00:01:05.923",
    }
  },
  ...
]
```

### Example2 - retrieving logs that contain "ERROR" string with surrounding logs:

```
$ qal -g my-log-group -q 'fields @timestamp,@message,@log,@logStream | @message like "ERROR"' -b 10ms
```

This command would output the JSON looking like below:

```
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
]
```
