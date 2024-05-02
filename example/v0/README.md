# Logs Go SDK Example

## Running example_v0.go

To run the example, run the following commands from this directory:
1. `export LOGS_API_KEY=<Your IBM Cloud API key>`
2. `export LOGS_SERVICE_URL=<logs_service_url>` `eg. "https://api.cxdev.eu-gb.logs.dev.appdomain.cloud"`
3. `go run example_v0.go`

## How-to

### Set up an authenticator
```go
authenticator := &core.IamAuthenticator{
    ApiKey:       os.Getenv("LOGS_API_KEY"),
    ClientId:     "bx",
    ClientSecret: "bx",
    URL:          "https://iam.test.cloud.ibm.com",
}
```

### Set up a Logs Service client
```go
logsServiceOptions := &logsv0.LogsV0Options{
    ServiceName:   "logs",
    Authenticator: authenticator,
    URL:           os.Getenv("LOGS_SERVICE_URL"), // Optional: Defaults to the service's constant DefaultServiceURL if not provided.
}

logsService, err := logsv0.NewLogsV0UsingExternalConfig(logsServiceOptions)
```

### List Alerts API
```go
getAlertsOptions := &logsv0.GetAlertsOptions{
    Headers:             map[string]string{},
}

alerts, detailedResponse, err := logsService.GetAlerts(getAlertsOptions)
```

### Get Alert API
```go
getAlertOptions := &logsv0.GetAlertOptions{
    ID:                  core.StringPtr("your_alert_id_here"), // Replace "your_alert_id_here" with the ID of the alert you want to retrieve.
    Headers:             map[string]string{},
}

alert, detailedResponse, err := logsService.GetAlert(getAlertOptions)
```

### Create Alert API
```go
alertsV2ConditionParametersModel := &logsv0.AlertsV2ConditionParameters{
    Threshold:         core.Float64Ptr(float64(1.0)),
    Timeframe:         core.StringPtr("timeframe_10_min"),
    GroupBy:           []string{"coralogix.metadata.applicationName"},
    IgnoreInfinity:    core.BoolPtr(true),
    RelativeTimeframe: core.StringPtr("hour_or_unspecified"),
    CardinalityFields: []string{},
}

alertsV2MoreThanConditionModel := &logsv0.AlertsV2MoreThanCondition{
    Parameters:       alertsV2ConditionParametersModel,
    EvaluationWindow: core.StringPtr("rolling_or_unspecified"),
}

alertsV2AlertConditionModel := &logsv0.AlertsV2AlertConditionConditionMoreThan{
    MoreThan: alertsV2MoreThanConditionModel,
}

alertsV2AlertNotificationGroupsModel := &logsv0.AlertsV2AlertNotificationGroups{
    GroupByFields: []string{"coralogix.metadata.applicationName"},
    Notifications: []logsv0.AlertsV2AlertNotificationIntf{},
}

alertsV1AlertFiltersMetadataFiltersModel := &logsv0.AlertsV1AlertFiltersMetadataFilters{
    Applications: []string{"testString"},
}

alertsV1AlertFiltersModel := &logsv0.AlertsV1AlertFilters{
    Severities: []string{"info"},
    Metadata:   alertsV1AlertFiltersMetadataFiltersModel,
    Alias:      core.StringPtr("testString"),
    Text:       core.StringPtr("initiator.id.keyword:/iam-ServiceId-10820fd6-c3fe-414e-8fd5-44ce95f7d34d.*/ AND action.keyword:/cloud-object-storage.object.create.*/ AND target.id.keyword:/crn:v1:bluemix:public:cloud-object-storage:global:a\\/81de6380e6232019c6567c9c8de6dece:69002255-e226-424e-b6c7-23c887fdb8bf:bucket:at-frankfurt.*/"),
    FilterType: core.StringPtr("text_or_unspecified"),
}

alertsV1TimeModel := &logsv0.AlertsV1Time{
    Hours:   core.Int64Ptr(int64(18)),
    Minutes: core.Int64Ptr(int64(30)),
    Seconds: core.Int64Ptr(int64(0)),
}

alertsV1TimeRangeModel := &logsv0.AlertsV1TimeRange{
    Start: alertsV1TimeModel,
    End:   alertsV1TimeModel,
}

alertsV1AlertActiveTimeframeModel := &logsv0.AlertsV1AlertActiveTimeframe{
    DaysOfWeek: []string{"sunday", "monday_or_unspecified", "tuesday", "wednesday", "thursday", "friday", "saturday"},
    Range:      alertsV1TimeRangeModel,
}

alertsV1AlertActiveWhenModel := &logsv0.AlertsV1AlertActiveWhen{
    Timeframes: []logsv0.AlertsV1AlertActiveTimeframe{*alertsV1AlertActiveTimeframeModel},
}

alertsV2AlertIncidentSettingsModel := &logsv0.AlertsV2AlertIncidentSettings{
    RetriggeringPeriodSeconds: core.Int64Ptr(int64(300)),
    NotifyOn:                  core.StringPtr("triggered_only"),
    UseAsNotificationSettings: core.BoolPtr(true),
}

createAlertOptions := &logsv0.CreateAlertOptions{
    Name:               core.StringPtr("alert"),
    IsActive:           core.BoolPtr(true),
    Condition:          alertsV2AlertConditionModel,
    NotificationGroups: []logsv0.AlertsV2AlertNotificationGroups{*alertsV2AlertNotificationGroupsModel},
    Description:        core.StringPtr("Test alert"),
    Severity:           core.StringPtr("info_or_unspecified"),
    Filters:            alertsV1AlertFiltersModel,
    ActiveWhen:         alertsV1AlertActiveWhenModel,
    MetaLabelsStrings:  []string{},
    IncidentSettings:   alertsV2AlertIncidentSettingsModel,
}

alert, detailedResponse, err := logsService.CreateAlert(createAlertOptions)
```

### Update Alert API
```go
alertsV2ConditionParametersModel := &logsv0.AlertsV2ConditionParameters{
    Threshold:         core.Float64Ptr(float64(1.0)),
    Timeframe:         core.StringPtr("timeframe_10_min"),
    GroupBy:           []string{"coralogix.metadata.applicationName"},
    IgnoreInfinity:    core.BoolPtr(true),
    RelativeTimeframe: core.StringPtr("hour_or_unspecified"),
    CardinalityFields: []string{},
}

alertsV2MoreThanConditionModel := &logsv0.AlertsV2MoreThanCondition{
    Parameters:       alertsV2ConditionParametersModel,
    EvaluationWindow: core.StringPtr("rolling_or_unspecified"),
}

alertsV2AlertConditionModel := &logsv0.AlertsV2AlertConditionConditionMoreThan{
    MoreThan: alertsV2MoreThanConditionModel,
}

alertsV2AlertNotificationGroupsModel := &logsv0.AlertsV2AlertNotificationGroups{
    GroupByFields: []string{"coralogix.metadata.applicationName"},
    Notifications: []logsv0.AlertsV2AlertNotificationIntf{},
}

alertsV1AlertFiltersMetadataFiltersModel := &logsv0.AlertsV1AlertFiltersMetadataFilters{
    Applications: []string{"testString"},
}

alertsV1AlertFiltersModel := &logsv0.AlertsV1AlertFilters{
    Severities: []string{"info"},
    Metadata:   alertsV1AlertFiltersMetadataFiltersModel,
    Alias:      core.StringPtr("testString"),
    Text:       core.StringPtr("initiator.id.keyword:/iam-ServiceId-10820fd6-c3fe-414e-8fd5-44ce95f7d34d.*/ AND action.keyword:/cloud-object-storage.object.create.*/ AND target.id.keyword:/crn:v1:bluemix:public:cloud-object-storage:global:a\\/81de6380e6232019c6567c9c8de6dece:69002255-e226-424e-b6c7-23c887fdb8bf:bucket:at-frankfurt.*/"),
    FilterType: core.StringPtr("text_or_unspecified"),
}

alertsV1TimeModel := &logsv0.AlertsV1Time{
    Hours:   core.Int64Ptr(int64(18)),
    Minutes: core.Int64Ptr(int64(30)),
    Seconds: core.Int64Ptr(int64(0)),
}

alertsV1TimeRangeModel := &logsv0.AlertsV1TimeRange{
    Start: alertsV1TimeModel,
    End:   alertsV1TimeModel,
}

alertsV1AlertActiveTimeframeModel := &logsv0.AlertsV1AlertActiveTimeframe{
    DaysOfWeek: []string{"sunday", "monday_or_unspecified", "tuesday", "wednesday", "thursday", "friday", "saturday"},
    Range:      alertsV1TimeRangeModel,
}

alertsV1AlertActiveWhenModel := &logsv0.AlertsV1AlertActiveWhen{
    Timeframes: []logsv0.AlertsV1AlertActiveTimeframe{*alertsV1AlertActiveTimeframeModel},
}

alertsV2AlertIncidentSettingsModel := &logsv0.AlertsV2AlertIncidentSettings{
    RetriggeringPeriodSeconds: core.Int64Ptr(int64(300)),
    NotifyOn:                  core.StringPtr("triggered_only"),
    UseAsNotificationSettings: core.BoolPtr(true),
}

updateAlertOptions := &logsv0.UpdateAlertOptions{
    ID:                 core.StringPtr("your_alert_id_here"), // Replace "your_alert_id_here" with the ID of the alert you want to update.
    Name:               core.StringPtr("alert"),
    IsActive:           core.BoolPtr(true),
    Condition:          alertsV2AlertConditionModel,
    NotificationGroups: []logsv0.AlertsV2AlertNotificationGroups{*alertsV2AlertNotificationGroupsModel},
    Description:        core.StringPtr("update test alert"),
    Severity:           core.StringPtr("info_or_unspecified"),
    Filters:            alertsV1AlertFiltersModel,
    ActiveWhen:         alertsV1AlertActiveWhenModel,
    MetaLabelsStrings:  []string{},
    IncidentSettings:   alertsV2AlertIncidentSettingsModel,
}

updateAlertResponse, detailedResponse, err := logsService.UpdateAlert(updateAlertOptions)
```

### Delete Alert API
```go
deleteAlertOptions := &logsv0.DeleteAlertOptions{
    ID:                  core.StringPtr("your_alert_id_here"), // Replace "your_alert_id_here" with the ID of the alert you want to delete.
}

detailedResponse, err := logsService.DeleteAlert(deleteAlertOptions)
```

The other API examples can be found in [example_v0.go](https://github.com/IBM/logs-go-sdk/tree/main/example/v0/example_v0) file.