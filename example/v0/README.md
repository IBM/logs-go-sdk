# Logs Go SDK Example

## Running example_v0.go

To run the example, run the following commands from this directory:
1. `export Logs_API_KEY=<Your IBM Cloud API key>`
2. `export Logs_Service_URL=<logs_service_url>` `eg. "https://api.cxdev.eu-gb.logs.dev.appdomain.cloud"`
3. `go run example_v0.go`

## How-to

### Set up an authenticator
```go
authenticator := &core.IamAuthenticator{
    ApiKey:       os.Getenv("Logs_API_KEY"),
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
    URL:           os.Getenv("Logs_Service_URL"), // Optional: Defaults to the service's constant DefaultServiceURL if not provided.
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
createAlertOptions := &logsv0.CreateAlertOptions{
    Name:                core.StringPtr("test-alert"),
    Description:         core.StringPtr(""),
    IsActive:            core.BoolPtr(false),
    Condition: &logsv0.AlertsV2AlertConditionConditionMoreThan{
        MoreThan: &logsv0.AlertsV2MoreThanCondition{
            Parameters: &logsv0.AlertsV2ConditionParameters{
                Threshold:         core.Float64Ptr(1),
                Timeframe:         core.StringPtr("timeframe_10_min"),
                GroupBy:           []string{"coralogix.metadata.applicationName"},
                RelativeTimeframe: core.StringPtr("hour_or_unspecified"),
                CardinalityFields: []string{},
            },
            EvaluationWindow: core.StringPtr("rolling_or_unspecified"),
        },
    },
    NotificationGroups: []logsv0.AlertsV2AlertNotificationGroups{{
        GroupByFields: []string{"coralogix.logId"},
        Notifications: []logsv0.AlertsV2AlertNotificationIntf{},
    }},
}
alert, detailedResponse, err := logsService.CreateAlert(createAlertOptions)
```

### Update Alert API
```go
updateAlertOptions := &logsv0.UpdateAlertOptions{
    ID:                  core.StringPtr("your_alert_id_here"), // Replace "your_alert_id_here" with the ID of the alert you want to update.
    Name:                core.StringPtr("test-alert"),
    Description:         core.StringPtr(""),
    IsActive:            core.BoolPtr(false),
    Condition: &logsv0.AlertsV2AlertConditionConditionMoreThan{
        MoreThan: &logsv0.AlertsV2MoreThanCondition{
            Parameters: &logsv0.AlertsV2ConditionParameters{
                Threshold:         core.Float64Ptr(0.0),
                Timeframe:         core.StringPtr("timeframe_10_min"),
                GroupBy:           []string{"coralogix.metadata.applicationName"},
                RelativeTimeframe: core.StringPtr("hour_or_unspecified"),
                CardinalityFields: []string{},
            },
            EvaluationWindow: core.StringPtr("rolling_or_unspecified"),
        },
    },
    NotificationGroups: []logsv0.AlertsV2AlertNotificationGroups{
        {
            GroupByFields: []string{"coralogix.logId"},
            Notifications: []logsv0.AlertsV2AlertNotificationIntf{},
        },
    },
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

### List E2M API
```go
listE2mOptions := &logsv0.ListE2mOptions{
}
event2MetricCollection, detailedResponse, err := logsService.ListE2m(listE2mOptions)
```

### Create E2M API
```go
event2MetricPrototypeModel := &logsv0.Event2MetricPrototypeApisEvents2metricsV2E2mCreateParamsQueryLogsQuery{
    Name:              core.StringPtr(nameForPayload),
    Description:       core.StringPtr("Test"),
    PermutationsLimit: core.Int64Ptr(int64(1)),
    Type:      core.StringPtr("logs2metrics"),
    LogsQuery: &logsv0.ApisLogs2metricsV2LogsQuery{
        Lucene:                 core.StringPtr("testString"),
        Alias:                  core.StringPtr("testString"),
        ApplicationnameFilters: []string{"testString"},
        SubsystemnameFilters:   []string{"testString"},
        SeverityFilters:        []string{"unspecified"},
    },
}
createE2mOptions := &logsv0.CreateE2mOptions{
    Event2MetricPrototype: event2MetricPrototypeModel,
}
event2Metric, response, err := logsService.CreateE2m(createE2mOptions)
```

### Get E2M API
```go
getE2mOptions := &logsv0.GetE2mOptions{
    ID:                  core.StringPtr("your_e2m_id_here"), //Replace "your_e2m_id_here" with the ID of the event2metrics you want to retrieve.
}
event2Metric, response, err := logsService.GetE2m(getE2mOptions)
```

### Replace E2M API
```go
event2MetricPrototypeModel := &logsv0.Event2MetricPrototypeApisEvents2metricsV2E2mCreateParamsQueryLogsQuery{
    Name:              core.StringPtr(nameForPayload),
    Description:       core.StringPtr("Test update"),
    PermutationsLimit: core.Int64Ptr(int64(1)),
    Type:      core.StringPtr("logs2metrics"),
    LogsQuery: &logsv0.ApisLogs2metricsV2LogsQuery{
        Lucene:                 core.StringPtr("testString"),
        Alias:                  core.StringPtr("testString"),
        ApplicationnameFilters: []string{"testString"},
        SubsystemnameFilters:   []string{"testString"},
        SeverityFilters:        []string{"unspecified"},
    },
}
replaceE2mOptions := &logsv0.ReplaceE2mOptions{
    ID:                    core.StringPtr("your_e2m_id_here"), //Replace "your_e2m_id_here" with the ID of the event2metrics you want to replace.
    Event2MetricPrototype: event2MetricPrototypeModel,
}
event2MetricResponse, detailedResponse, err := logsService.ReplaceE2m(replaceE2mOptions)
```

### Delete E2M API
```go
deleteE2mOptions := &logsv0.DeleteE2mOptions{
    ID:                  core.StringPtr("your_e2m_id_here"), //Replace "your_e2m_id_here" with the ID of the event2metrics you want to delete.
}
response, err := logsService.DeleteE2m(deleteE2mOptions)
```

### Dataprime API
```go
type callBack struct{}

func (cb callBack) OnClose() {
	fmt.Println("closing callback")
}

func (cb callBack) OnError(err error) {
	fmt.Println("error callback", err)
}

func (cb callBack) OnData(detailedResponse *core.DetailedResponse) {
	directResult := detailedResponse.Result.(*logsv0.QueryResponseStreamItem)
	if directResult.QueryID != nil {
		//
	}
	if directResult.Result != nil {
		for _, result := range directResult.Result.Results {
			fmt.Println(*result.UserData)
		}
	}
}

func main() {
    queryOptions := logsv0.QueryOptions{
		Query:               core.StringPtr("source logs | limit 10"),
		Metadata: &logsv0.ApisDataprimeV1Metadata{
			StartDate: CreateDateTime("2024-03-01T20:47:12.940Z"),
			EndDate:   CreateDateTime("2024-03-06T20:47:12.940Z"),
			Tier:      core.StringPtr("frequent_search"),
			Syntax:    core.StringPtr("dataprime"),
		},
	}

	var wg sync.WaitGroup

	wg.Add(1.)
	go func() {
		logsService.QueryWithContext(context.Background(), &queryOptions, callBack{})
		wg.Done()
	}()

	wg.Wait()
}

func CreateDateTime(mockData string) *strfmt.DateTime {
	d, err := core.ParseDateTime(mockData)
	if err != nil {
		return nil
	}
	return &d
}
```

### Create Rule Group API
```go
createRuleGroupOptions := &logsv0.CreateRuleGroupOptions{
    Name:                core.StringPtr(getRandomName()),
    Description:         core.StringPtr("description"),
    Enabled:             core.BoolPtr(true),
    Hidden:              core.BoolPtr(false),
    Creator:             core.StringPtr("bot@coralogix.com"),
    RuleMatchers: []logsv0.RulesV1RuleMatcherIntf{&logsv0.RulesV1RuleMatcherConstraintSubsystemName{
        SubsystemName: &logsv0.RulesV1SubsystemNameConstraint{
            Value: core.StringPtr("mysql-cloudwatch"),
        },
    }},
    RuleSubgroups: []logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroup{
        {
            Rules: []logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRule{
                {
                    Name:        core.StringPtr("mysql-parse"),
                    Description: core.StringPtr("mysql-parse"),
                    SourceField: core.StringPtr("text"),
                    Parameters: &logsv0.RulesV1RuleParametersRuleParametersParseParameters{
                        ParseParameters: &logsv0.RulesV1ParseParameters{
                            DestinationField: core.StringPtr("text"),
                            Rule:             core.StringPtr("(?P<timestamp>[^,]+),(?P<hostname>[^,]+),(?P<username>[^,]+),(?P<ip>[^,]+),(?P<connectionId>[0-9]+),(?P<queryId>[0-9]+),(?P<operation>[^,]+),(?P<database>[^,]+),?(?P<object>.*)?,(?P<returnCode>[0-9]+)"),
                        },
                    },
                    Enabled: core.BoolPtr(true),
                    Order:   core.Int64Ptr(int64(1)),
                },
            },
            Enabled: core.BoolPtr(true),
            Order:   core.Int64Ptr(int64(1)),
        },
    },
    Order: core.Int64Ptr(int64(39)),
}
ruleGroup, response, err := logsService.CreateRuleGroup(createRuleGroupOptions)
```

### Update Rule Group API
```go
updateRuleGroupOptions := &logsv0.UpdateRuleGroupOptions{
    GroupID:             core.StringPtr("your_RG_id_here"), //Replace "your_RG_id_here" with the ID of the RuleGroup you want to update.
    Name:                core.StringPtr(*ruleGroup.Name),
    Description:         core.StringPtr("mysql-cloudwatch audit updated logs parser"),
    Enabled:             core.BoolPtr(true),
    Hidden:              core.BoolPtr(false),
    Creator:             core.StringPtr("bot@coralogix.com"),
    RuleMatchers: []logsv0.RulesV1RuleMatcherIntf{&logsv0.RulesV1RuleMatcherConstraintSubsystemName{
        SubsystemName: &logsv0.RulesV1SubsystemNameConstraint{
            Value: core.StringPtr("mysql-cloudwatch"),
        },
    }},
    RuleSubgroups: []logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroup{{
        Rules: []logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRule{{
            Name:        core.StringPtr("mysql-parse"),
            Description: core.StringPtr("mysql-parse"),
            SourceField: core.StringPtr("text"),
            Parameters: &logsv0.RulesV1RuleParametersRuleParametersParseParameters{
                ParseParameters: &logsv0.RulesV1ParseParameters{
                    DestinationField: core.StringPtr("text"),
                    Rule:             core.StringPtr("(?P<timestamp>[^,]+),(?P<hostname>[^,]+),(?P<username>[^,]+),(?P<ip>[^,]+),(?P<connectionId>[0-9]+),(?P<queryId>[0-9]+),(?P<operation>[^,]+),(?P<database>[^,]+),?(?P<object>.*)?,(?P<returnCode>[0-9]+)"),
                },
            },
            Enabled: core.BoolPtr(true),
            Order:   core.Int64Ptr(int64(1)),
        }},
        Enabled: core.BoolPtr(true),
        Order:   core.Int64Ptr(int64(1)),
    }},
    Order: core.Int64Ptr(int64(39)),
    TeamID: &logsv0.RulesV1TeamID{
        ID: core.Int64Ptr(int64(0)),
    },
}
ruleGroup, detailedResponse, err = logsService.UpdateRuleGroup(updateRuleGroupOptions)
```

### Get Rule Group API
```go
getRuleGroupOptions := &logsv0.GetRuleGroupOptions{
    GroupID:             core.StringPtr("your_RG_id_here"), //Replace "your_RG_id_here" with the ID of the RuleGroup you want to retrieve.
}
ruleGroup, detailedResponse, err = logsService.GetRuleGroup(getRuleGroupOptions)
```

### Delete Rule Group API
```go
deleteRuleGroupOptions := &logsv0.DeleteRuleGroupOptions{
    GroupID:             core.StringPtr("your_RG_id_here"), //Replace "your_RG_id_here" with the ID of the RuleGroup you want to delete.
}
detailedResponse, err = logsService.DeleteRuleGroup(deleteRuleGroupOptions)
```

### Create Policy API
```go
createPolicyOptions := &logsv0.CreatePolicyOptions{
    PolicyPrototype: &logsv0.PolicyPrototypeQuotaV1CreatePolicyRequestSourceTypeRulesLogRules{
        Name:        core.StringPtr(getRandomName()),
        Description: core.StringPtr("description updated"),
        Priority:    core.StringPtr("type_medium"),
        ApplicationRule: &logsv0.QoutaRule{
            RuleTypeID: core.StringPtr("is"),
            Name:       core.StringPtr("app"),
        },
        SubsystemRule: &logsv0.QoutaRule{
            RuleTypeID: core.StringPtr("is"),
            Name:       core.StringPtr("app"),
        },
        LogRules: &logsv0.QuotaV1LogRules{
            Severities: []string{"debug"},
        },
    },
}
policy, detailedResponse, err := logsService.CreatePolicy(createPolicyOptions)
```

### Update Policy API
```go
updatePolicyOptions := &logsv0.UpdatePolicyOptions{
    ID:                  core.StringPtr("your_policy_id_here"), //Replace "your_policy_id_here" with the ID of the Policy you want to retrieve. 
    PolicyPrototype: &logsv0.PolicyPrototypeQuotaV1CreatePolicyRequestSourceTypeRulesLogRules{
        Name:        core.StringPtr(policyName),
        Description: core.StringPtr("description"),
        Priority:    core.StringPtr("type_medium"),
        ApplicationRule: &logsv0.QoutaRule{
            RuleTypeID: core.StringPtr("is"),
            Name:       core.StringPtr("app"),
        },
        SubsystemRule: &logsv0.QoutaRule{
            RuleTypeID: core.StringPtr("is"),
            Name:       core.StringPtr("app"),
        },
        LogRules: &logsv0.QuotaV1LogRules{
            Severities: []string{"debug"},
        },
    },
}
policy, detailedResponse, err = logsService.UpdatePolicy(updatePolicyOptions)
```

### Get Policy API
```go
getPolicyOptions := &logsv0.GetPolicyOptions{
    ID:                  core.StringPtr("your_policy_id_here"), //Replace "your_policy_id_here" with the ID of the Policy you want to retrieve.
}
policy, detailedResponse, err = logsService.GetPolicy(getPolicyOptions)
```

### Get Company Policies API
```go
getCompanyPoliciesOptions := &logsv0.GetCompanyPoliciesOptions{
    EnabledOnly:         core.BoolPtr(true),
    SourceType:          core.StringPtr("logs"),
}
policyCollection, detailedResponse, err := logsService.GetCompanyPolicies(getCompanyPoliciesOptions)
```

### Delete Policy API
```go
deletePolicyOptions := &logsv0.DeletePolicyOptions{
    ID:                  core.StringPtr("your_policy_id_here"), //Replace "your_policy_id_here" with the ID of the Policy you want to retrieve.
}
detailedResponse, err = logsService.DeletePolicy(deletePolicyOptions)
```

### Create Dashboard API
```go
apisDashboardsV1UUIDModel := &logsv0.ApisDashboardsV1UUID{
    Value: core.StringPtr("10c27980-3532-21b0-8069-0c9110f03c90"),
}

apisDashboardsV1AstRowAppearanceModel := &logsv0.ApisDashboardsV1AstRowAppearance{
    Height: core.Int64Ptr(int64(19)),
}

apisDashboardsV1AstWidgetsCommonLegendModel := &logsv0.ApisDashboardsV1AstWidgetsCommonLegend{
    IsVisible:    core.BoolPtr(true),
    Columns:      []string{"unspecified"},
    GroupByQuery: core.BoolPtr(true),
}

apisDashboardsV1AstWidgetsLineChartTooltipModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartTooltip{
    ShowLabels: core.BoolPtr(false),
    Type:       core.StringPtr("all"),
}

apisDashboardsV1AstWidgetsCommonPromQlQueryModel := &logsv0.ApisDashboardsV1AstWidgetsCommonPromQlQuery{
    Value: core.StringPtr("sum(rate(cx_data_usage_bytes_total[20m]))by(pillar,tier)"),
}

apisDashboardsV1AstFilterEqualsSelectionAllSelectionModel := &logsv0.ApisDashboardsV1AstFilterEqualsSelectionAllSelection{}

apisDashboardsV1AstFilterEqualsSelectionModel := &logsv0.ApisDashboardsV1AstFilterEqualsSelectionValueAll{
    All: apisDashboardsV1AstFilterEqualsSelectionAllSelectionModel,
}

apisDashboardsV1AstFilterEqualsModel := &logsv0.ApisDashboardsV1AstFilterEquals{
    Selection: apisDashboardsV1AstFilterEqualsSelectionModel,
}

apisDashboardsV1AstFilterOperatorModel := &logsv0.ApisDashboardsV1AstFilterOperatorValueEquals{
    Equals: apisDashboardsV1AstFilterEqualsModel,
}

apisDashboardsV1AstWidgetsLineChartMetricsQueryModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartMetricsQuery{
    PromqlQuery: apisDashboardsV1AstWidgetsCommonPromQlQueryModel,
}

apisDashboardsV1AstWidgetsLineChartQueryModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartQueryValueMetrics{
    Metrics: apisDashboardsV1AstWidgetsLineChartMetricsQueryModel,
}

apisDashboardsV1AstWidgetsLineChartQueryDefinitionModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartQueryDefinition{
    ID:                 core.StringPtr("e4560525-521c-49e7-a7de-a2925626c304"),
    Query:              apisDashboardsV1AstWidgetsLineChartQueryModel,
    SeriesNameTemplate: core.StringPtr("testString"),
    SeriesCountLimit:   core.StringPtr("20"),
    Unit:               core.StringPtr("unspecified"),
    ScaleType:          core.StringPtr("linear"),
    Name:               core.StringPtr("Query1"),
    IsVisible:          core.BoolPtr(true),
    ColorScheme:        core.StringPtr("classic"),
    DataModeType:       core.StringPtr("high_unspecified"),
}

apisDashboardsV1AstWidgetsLineChartModel := &logsv0.ApisDashboardsV1AstWidgetsLineChart{
    Legend:           apisDashboardsV1AstWidgetsCommonLegendModel,
    Tooltip:          apisDashboardsV1AstWidgetsLineChartTooltipModel,
    QueryDefinitions: []logsv0.ApisDashboardsV1AstWidgetsLineChartQueryDefinition{*apisDashboardsV1AstWidgetsLineChartQueryDefinitionModel},
}

apisDashboardsV1AstWidgetDefinitionModel := &logsv0.ApisDashboardsV1AstWidgetDefinitionValueLineChart{
    LineChart: apisDashboardsV1AstWidgetsLineChartModel,
}

apisDashboardsV1AstWidgetAppearanceModel := &logsv0.ApisDashboardsV1AstWidgetAppearance{
    Width: core.Int64Ptr(int64(0)),
}

apisDashboardsV1AstWidgetModel := &logsv0.ApisDashboardsV1AstWidget{
    ID:          apisDashboardsV1UUIDModel,
    Title:       core.StringPtr("Size"),
    Description: core.StringPtr("testString"),
    Definition:  apisDashboardsV1AstWidgetDefinitionModel,
    Appearance:  apisDashboardsV1AstWidgetAppearanceModel,
}

apisDashboardsV1AstRowModel := &logsv0.ApisDashboardsV1AstRow{
    ID:         apisDashboardsV1UUIDModel,
    Appearance: apisDashboardsV1AstRowAppearanceModel,
    Widgets:    []logsv0.ApisDashboardsV1AstWidget{*apisDashboardsV1AstWidgetModel},
}

apisDashboardsV1AstSectionModel := &logsv0.ApisDashboardsV1AstSection{
    ID:   apisDashboardsV1UUIDModel,
    Rows: []logsv0.ApisDashboardsV1AstRow{*apisDashboardsV1AstRowModel},
}

apisDashboardsV1AstLayoutModel := &logsv0.ApisDashboardsV1AstLayout{
    Sections: []logsv0.ApisDashboardsV1AstSection{*apisDashboardsV1AstSectionModel},
}

apisDashboardsV1CommonObservationFieldModel := &logsv0.ApisDashboardsV1CommonObservationField{
    Keypath: []string{"applicationname"},
    Scope:   core.StringPtr("label"),
}

apisDashboardsV1AstFilterLogsFilterModel := &logsv0.ApisDashboardsV1AstFilterLogsFilter{
    Field:            core.StringPtr("testString"),
    Operator:         apisDashboardsV1AstFilterOperatorModel,
    ObservationField: apisDashboardsV1CommonObservationFieldModel,
}

apisDashboardsV1AstFilterSourceModel := &logsv0.ApisDashboardsV1AstFilterSourceValueLogs{
    Logs: apisDashboardsV1AstFilterLogsFilterModel,
}

apisDashboardsV1AstFilterModel := &logsv0.ApisDashboardsV1AstFilter{
    Source:    apisDashboardsV1AstFilterSourceModel,
    Enabled:   core.BoolPtr(true),
    Collapsed: core.BoolPtr(false),
}

apisDashboardsV1AstAnnotationMetricsSourceStartTimeMetricModel := &logsv0.ApisDashboardsV1AstAnnotationMetricsSourceStartTimeMetric{}
apisDashboardsV1AstAnnotationMetricsSourceStartTimeMetricModel.SetProperty("foo", core.StringPtr("testString"))

dashboardModel := &logsv0.DashboardApisDashboardsV1AstDashboardTimeFrameRelativeTimeFrame{
    Name:              core.StringPtr(getRandomName()),
    Description:       core.StringPtr("testString"),
    Layout:            apisDashboardsV1AstLayoutModel,
    Filters:           []logsv0.ApisDashboardsV1AstFilter{*apisDashboardsV1AstFilterModel},
    RelativeTimeFrame: core.StringPtr("86400s"),
}

createDashboardOptions := &logsv0.CreateDashboardOptions{
    Dashboard:           dashboardModel,
}

dashboard, detailedResponse, err := logsService.CreateDashboard(createDashboardOptions)
```

### Replace Dashboard API
```go
apisDashboardsV1UUIDModel1 := &logsv0.ApisDashboardsV1UUID{
    Value: core.StringPtr("10c27980-3532-21b0-8069-0c9110f03c90"),
}

apisDashboardsV1AstRowAppearanceModel1 := &logsv0.ApisDashboardsV1AstRowAppearance{
    Height: core.Int64Ptr(int64(19)),
}

apisDashboardsV1AstWidgetsCommonLegendModel1 := &logsv0.ApisDashboardsV1AstWidgetsCommonLegend{
    IsVisible:    core.BoolPtr(true),
    Columns:      []string{"unspecified"},
    GroupByQuery: core.BoolPtr(true),
}

apisDashboardsV1AstWidgetsLineChartTooltipModel1 := &logsv0.ApisDashboardsV1AstWidgetsLineChartTooltip{
    ShowLabels: core.BoolPtr(false),
    Type:       core.StringPtr("all"),
}

apisDashboardsV1AstWidgetsCommonPromQlQueryModel1 := &logsv0.ApisDashboardsV1AstWidgetsCommonPromQlQuery{
    Value: core.StringPtr("sum(rate(cx_data_usage_bytes_total[20m]))by(pillar,tier)"),
}

apisDashboardsV1AstFilterEqualsSelectionAllSelectionModel1 := &logsv0.ApisDashboardsV1AstFilterEqualsSelectionAllSelection{}

apisDashboardsV1AstFilterEqualsSelectionModel1 := &logsv0.ApisDashboardsV1AstFilterEqualsSelectionValueAll{
    All: apisDashboardsV1AstFilterEqualsSelectionAllSelectionModel1,
}

apisDashboardsV1AstFilterEqualsModel1 := &logsv0.ApisDashboardsV1AstFilterEquals{
    Selection: apisDashboardsV1AstFilterEqualsSelectionModel1,
}

apisDashboardsV1AstFilterOperatorModel1 := &logsv0.ApisDashboardsV1AstFilterOperatorValueEquals{
    Equals: apisDashboardsV1AstFilterEqualsModel1,
}

apisDashboardsV1AstWidgetsLineChartMetricsQueryModel1 := &logsv0.ApisDashboardsV1AstWidgetsLineChartMetricsQuery{
    PromqlQuery: apisDashboardsV1AstWidgetsCommonPromQlQueryModel1,
}

apisDashboardsV1AstWidgetsLineChartQueryModel1 := &logsv0.ApisDashboardsV1AstWidgetsLineChartQueryValueMetrics{
    Metrics: apisDashboardsV1AstWidgetsLineChartMetricsQueryModel1,
}

apisDashboardsV1AstWidgetsLineChartQueryDefinitionModel1 := &logsv0.ApisDashboardsV1AstWidgetsLineChartQueryDefinition{
    ID:                 core.StringPtr("e4560525-521c-49e7-a7de-a2925626c304"),
    Query:              apisDashboardsV1AstWidgetsLineChartQueryModel1,
    SeriesNameTemplate: core.StringPtr("testString"),
    SeriesCountLimit:   core.StringPtr("20"),
    Unit:               core.StringPtr("unspecified"),
    ScaleType:          core.StringPtr("linear"),
    Name:               core.StringPtr("Query1"),
    IsVisible:          core.BoolPtr(true),
    ColorScheme:        core.StringPtr("classic"),
    DataModeType:       core.StringPtr("high_unspecified"),
}

apisDashboardsV1AstWidgetsLineChartModel1 := &logsv0.ApisDashboardsV1AstWidgetsLineChart{
    Legend:           apisDashboardsV1AstWidgetsCommonLegendModel1,
    Tooltip:          apisDashboardsV1AstWidgetsLineChartTooltipModel1,
    QueryDefinitions: []logsv0.ApisDashboardsV1AstWidgetsLineChartQueryDefinition{*apisDashboardsV1AstWidgetsLineChartQueryDefinitionModel1},
}

apisDashboardsV1AstWidgetDefinitionModel1 := &logsv0.ApisDashboardsV1AstWidgetDefinitionValueLineChart{
    LineChart: apisDashboardsV1AstWidgetsLineChartModel1,
}

apisDashboardsV1AstWidgetAppearanceModel1 := &logsv0.ApisDashboardsV1AstWidgetAppearance{
    Width: core.Int64Ptr(int64(0)),
}

apisDashboardsV1AstWidgetModel1 := &logsv0.ApisDashboardsV1AstWidget{
    ID:          apisDashboardsV1UUIDModel1,
    Title:       core.StringPtr("Size"),
    Description: core.StringPtr("testString"),
    Definition:  apisDashboardsV1AstWidgetDefinitionModel1,
    Appearance:  apisDashboardsV1AstWidgetAppearanceModel1,
}

apisDashboardsV1AstRowModel1 := &logsv0.ApisDashboardsV1AstRow{
    ID:         apisDashboardsV1UUIDModel1,
    Appearance: apisDashboardsV1AstRowAppearanceModel1,
    Widgets:    []logsv0.ApisDashboardsV1AstWidget{*apisDashboardsV1AstWidgetModel1},
}

apisDashboardsV1AstSectionModel1 := &logsv0.ApisDashboardsV1AstSection{
    ID:   apisDashboardsV1UUIDModel1,
    Rows: []logsv0.ApisDashboardsV1AstRow{*apisDashboardsV1AstRowModel1},
}

apisDashboardsV1AstLayoutModel1 := &logsv0.ApisDashboardsV1AstLayout{
    Sections: []logsv0.ApisDashboardsV1AstSection{*apisDashboardsV1AstSectionModel1},
}

apisDashboardsV1CommonObservationFieldModel1 := &logsv0.ApisDashboardsV1CommonObservationField{
    Keypath: []string{"applicationname"},
    Scope:   core.StringPtr("label"),
}

apisDashboardsV1AstFilterLogsFilterModel1 := &logsv0.ApisDashboardsV1AstFilterLogsFilter{
    Field:            core.StringPtr("testString"),
    Operator:         apisDashboardsV1AstFilterOperatorModel1,
    ObservationField: apisDashboardsV1CommonObservationFieldModel1,
}

apisDashboardsV1AstFilterSourceModel1 := &logsv0.ApisDashboardsV1AstFilterSourceValueLogs{
    Logs: apisDashboardsV1AstFilterLogsFilterModel1,
}

apisDashboardsV1AstFilterModel1 := &logsv0.ApisDashboardsV1AstFilter{
    Source:    apisDashboardsV1AstFilterSourceModel1,
    Enabled:   core.BoolPtr(true),
    Collapsed: core.BoolPtr(false),
}

apisDashboardsV1AstAnnotationMetricsSourceStartTimeMetricModel1 := &logsv0.ApisDashboardsV1AstAnnotationMetricsSourceStartTimeMetric{}
apisDashboardsV1AstAnnotationMetricsSourceStartTimeMetricModel1.SetProperty("foo", core.StringPtr("testString"))

dashboardModel1 := &logsv0.DashboardApisDashboardsV1AstDashboardTimeFrameRelativeTimeFrame{
    Name:              core.StringPtr("your_dashboard_name_here"), //Replace "your_dashboard_name_here" with the Name of the dashboard you want to replace.
    Description:       core.StringPtr("testString update"),
    Layout:            apisDashboardsV1AstLayoutModel1,
    Filters:           []logsv0.ApisDashboardsV1AstFilter{*apisDashboardsV1AstFilterModel1},
    RelativeTimeFrame: core.StringPtr("86400s"),
}

replaceDashboardOptions := &logsv0.ReplaceDashboardOptions{
    DashboardID:         core.StringPtr("your_dashboard_id_here"), //Replace "your_dashboard_id_here" with the ID of the dashboard you want to replace.
    Dashboard:           dashboardModel1,
}

dashboardResponse, detailedResponse, err := logsService.ReplaceDashboard(replaceDashboardOptions)
```

### Get Dashboard API
```go
getDashboardOptions := &logsv0.GetDashboardOptions{
    DashboardID:         core.StringPtr("your_dashboard_id_here"), //Replace "your_dashboard_id_here" with the ID of the dashboard you want to retrieve.
}

dashboard, detailedResponse, err = logsService.GetDashboard(getDashboardOptions)
```

### Delete Dashboard API
```go
deleteDashboardOptions := &logsv0.DeleteDashboardOptions{
    DashboardID:         core.StringPtr("your_dashboard_id_here"), //Replace "your_dashboard_id_here" with the ID of the dashboard you want to delete.
}

detailedResponse, err = logsService.DeleteDashboard(deleteDashboardOptions)
```

### Create Outgoing Webhook API
```go
outgoingWebhooksV1IbmEventNotificationsConfigModel := &logsv0.OutgoingWebhooksV1IbmEventNotificationsConfig{
    RegionID: core.StringPtr("us-south"),
}

outgoingWebhookPrototypeModel := &logsv0.OutgoingWebhookPrototypeOutgoingWebhooksV1OutgoingWebhookInputDataConfigIbmEventNotifications{
    Type:                  core.StringPtr("ibm_event_notifications"),
    Name:                  core.StringPtr("test-webhook"),
    URL:                   core.StringPtr("testString"),
    IbmEventNotifications: outgoingWebhooksV1IbmEventNotificationsConfigModel,
}

createOutgoingWebhookOptions := &logsv0.CreateOutgoingWebhookOptions{
    OutgoingWebhookPrototype: outgoingWebhookPrototypeModel,
}

outgoingWebhook, detailedResponse, err := logsService.CreateOutgoingWebhook(createOutgoingWebhookOptions)
```

### Update Outgoing Webhook API
```go
outgoingWebhooksV1IbmEventNotificationsConfigModel := &logsv0.OutgoingWebhooksV1IbmEventNotificationsConfig{
    RegionID: core.StringPtr("us-south"),
}

outgoingWebhookPrototypeModel := &logsv0.OutgoingWebhookPrototypeOutgoingWebhooksV1OutgoingWebhookInputDataConfigIbmEventNotifications{
    Type:                  core.StringPtr("ibm_event_notifications"),
    Name:                  core.StringPtr("test-webhook"),
    URL:                   core.StringPtr("testString"),
    IbmEventNotifications: outgoingWebhooksV1IbmEventNotificationsConfigModel,
}

updateOutgoingWebhookOptions := &logsv0.UpdateOutgoingWebhookOptions{
    ID:                       core.StringPtr(outgoingWebhookID),
    OutgoingWebhookPrototype: outgoingWebhookPrototypeModel,
}

outgoingWebhook, detailedResponse, err = logsService.UpdateOutgoingWebhook(updateOutgoingWebhookOptions)
```

### List Outgoing Webhook API
```go
listOutgoingWebhooksOptions := &logsv0.ListOutgoingWebhooksOptions{
    Type:                core.StringPtr("ibm_event_notifications"),
}
outgoingWebhookCollection, detailedResponse, err := logsService.ListOutgoingWebhooks(listOutgoingWebhooksOptions)
```

### Get Outgoing Webhook API
```go
getOutgoingWebhookOptions := &logsv0.GetOutgoingWebhookOptions{
    ID:                  core.StringPtr("your_outgoingWebhook_ID_here"),  // Replace "your_outgoingWebhook_ID_here" with the ID of the alert you want to retrieve.
}
outgoingWebhook, detailedResponse, err = logsService.GetOutgoingWebhook(getOutgoingWebhookOptions)
```

### Delete Outgoing Webhook API
```go
deleteOutgoingWebhookOptions := &logsv0.DeleteOutgoingWebhookOptions{
    ID:                  core.StringPtr("your_outgoingWebhook_ID_here"),  // Replace "your_outgoingWebhook_ID_here" with the ID of the alert you want to delete.
}
detailedResponse, err = logsService.DeleteOutgoingWebhook(deleteOutgoingWebhookOptions)
```