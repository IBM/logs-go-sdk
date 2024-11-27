package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sync"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/logs-go-sdk/logsv0"
	"github.com/go-openapi/strfmt"
)

func getRandomName() string {
	number := rand.Intn(1000)
	return fmt.Sprintf("test-%d", number)
}

func main() {
	// Set up the authenticator
	// begin-common
	authenticator := &core.IamAuthenticator{
		ApiKey:       os.Getenv("LOGS_API_KEY"),
		ClientId:     "bx",
		ClientSecret: "bx",
		URL:          "https://iam.test.cloud.ibm.com",
	}

	// Initialize the service options.
	logsServiceOptions := &logsv0.LogsV0Options{
		ServiceName:   "logs",
		Authenticator: authenticator,
		URL:           os.Getenv("LOGS_SERVICE_URL"), // Optional: Defaults to the service's constant DefaultServiceURL if not provided.
	}

	// Create a new service instance.
	logsService, err := logsv0.NewLogsV0UsingExternalConfig(logsServiceOptions)
	if err != nil {
		fmt.Println("Error creating service:", err)
		return
	}

	// end-common

	fmt.Println("\n############################")
	fmt.Println("################# GET Alerts ############")
	fmt.Println("#########################################")
	// begin-get_alerts

	// Set up the GetAlertOptions.
	getAlertsOptions := &logsv0.GetAlertsOptions{
		Headers: map[string]string{},
	}

	// List Alerts.
	alerts, detailedResponse, err := logsService.GetAlerts(getAlertsOptions)
	if err != nil {
		fmt.Println("Error getting alert:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	alertsList, err := json.MarshalIndent(alerts, "", "    ")
	if err != nil {
		log.Fatalf("Error occurred during marshaling. Error: %s", err.Error())
	}

	fmt.Println("\n#Print List ALERTS Response")
	fmt.Println("Alerts:", string(alertsList))
	// end-get_alerts

	fmt.Println("\n############################")
	fmt.Println("################# Create Alert ############")
	fmt.Println("#########################################")
	// begin-create_alert

	// Set up the CreateAlertOptions
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

	// convert the payload to json to print the payload
	createAlertPayload, err := json.MarshalIndent(createAlertOptions, "", "    ")
	if err != nil {
		log.Fatalf("Error occurred during marshaling. Error: %s", err.Error())
	}
	fmt.Println("\n#Print CREATE ALERT Payload")
	fmt.Println(string(createAlertPayload))

	// CreateAlert function.
	alert, detailedResponse, err := logsService.CreateAlert(createAlertOptions)
	if err != nil {
		fmt.Println("Error creating alert:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	// Print Alert ID
	fmt.Println("\nAlert ID :", *alert.ID)
	// end-create_alert

	fmt.Println("\n############################")
	fmt.Println("################# GET Alert ############")
	fmt.Println("#########################################")
	// begin-get_alert

	// Set up the GetAlertOptions.
	getAlertOptions := &logsv0.GetAlertOptions{
		ID:      alert.ID,
		Headers: map[string]string{},
	}

	// GetAlert function.
	alert, detailedResponse, err = logsService.GetAlert(getAlertOptions)
	if err != nil {
		fmt.Println("Error getting alert:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	// Print the result.
	alertDetails, err := json.MarshalIndent(alert, "", "    ")
	if err != nil {
		log.Fatalf("Error occurred during marshaling. Error: %s", err.Error())
	}

	fmt.Println("\n#Print Get ALERT Response")
	fmt.Println("Alert:", string(alertDetails))
	// end-get_alert

	fmt.Println("\n############################")
	fmt.Println("################# Update Alert ############")
	fmt.Println("#########################################")
	// begin-update_alert

	updateAlertOptions := &logsv0.UpdateAlertOptions{
		ID:                 alert.ID,
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

	// convert the payload to json to print the payload
	updateAlertPayload, err := json.MarshalIndent(updateAlertOptions, "", "    ")
	if err != nil {
		log.Fatalf("Error occurred during marshaling. Error: %s", err.Error())
	}
	fmt.Println("\n#Print UPDATE ALERT Payload")
	fmt.Println(string(updateAlertPayload))

	// UpdateAlert function.
	updateAlertResponse, detailedResponse, err := logsService.UpdateAlert(updateAlertOptions)
	if err != nil {
		fmt.Println("Error updating alert:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	fmt.Println("\nAlert :", *updateAlertResponse)
	// end-update_alert

	fmt.Println("\n############################")
	fmt.Println("################# Delete Alert ############")
	fmt.Println("#########################################")
	// begin-delete_alert

	deleteAlertOptions := &logsv0.DeleteAlertOptions{
		ID: alert.ID,
	}

	// DeleteAlert
	detailedResponse, err = logsService.DeleteAlert(deleteAlertOptions)
	if err != nil {
		fmt.Println("Error deleting alert:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	fmt.Println("\nsuccessfully deleted alert", alert.ID)
	// end-delete_alert

	fmt.Println("\n############################")
	fmt.Println("################# Create E2M ############")
	fmt.Println("#########################################")
	// begin-create_e2m

	apisLogs2metricsV2LogsQueryModel := &logsv0.ApisLogs2metricsV2LogsQuery{
		Lucene:          core.StringPtr("text:test"),
		SeverityFilters: []string{"warning"},
	}

	event2MetricPrototypeModel := &logsv0.Event2MetricPrototypeApisEvents2metricsV2E2mCreateParamsQueryLogsQuery{
		Name:              core.StringPtr(getRandomName()),
		Description:       core.StringPtr("Test"),
		PermutationsLimit: core.Int64Ptr(int64(1)),
		Type:              core.StringPtr("logs2metrics"),
		LogsQuery:         apisLogs2metricsV2LogsQueryModel,
	}

	createE2mOptions := &logsv0.CreateE2mOptions{
		Event2MetricPrototype: event2MetricPrototypeModel,
	}
	event2Metric, detailedResponse, err := logsService.CreateE2m(createE2mOptions)
	if err != nil {
		fmt.Println("Error creating e2m:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	var event2MetricsID string
	e2m, ok := event2Metric.(*logsv0.Event2Metric)
	if ok {
		event2MetricsID = e2m.ID.String()
	}
	fmt.Println("event2MetricsID:", event2MetricsID)

	// end-create_e2m

	fmt.Println("\n############################")
	fmt.Println("################# List E2M ############")
	fmt.Println("#########################################")

	// begin-list_e2m

	listE2mOptions := &logsv0.ListE2mOptions{}
	event2MetricCollection, detailedResponse, err := logsService.ListE2m(listE2mOptions)
	if err != nil {
		fmt.Println("Error listing e2m:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	// Print the result.
	event2MetricCol, err := json.MarshalIndent(event2MetricCollection, "", "    ")
	if err != nil {
		log.Fatalf("Error occurred during marshaling. Error: %s", err.Error())
	}
	fmt.Println("\n#Print List E2M Response")
	fmt.Println("Event2MetricCollection:", string(event2MetricCol))

	// end-list_e2m

	fmt.Println("\n############################")
	fmt.Println("################# Get E2M ############")
	fmt.Println("#########################################")

	// begin-get_e2m

	getE2mOptions := &logsv0.GetE2mOptions{
		ID: core.StringPtr(event2MetricsID),
	}
	event2MetricDetails, detailedResponse, err := logsService.GetE2m(getE2mOptions)
	if err != nil {
		fmt.Println("Error getting e2m:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	// Print the result.
	event2MetricDetail, err := json.MarshalIndent(event2MetricDetails, "", "    ")
	if err != nil {
		log.Fatalf("Error occurred during marshaling. Error: %s", err.Error())
	}
	fmt.Println("\n#Print Get E2M Response")
	fmt.Println("Event2MetricDetails:", string(event2MetricDetail))
	// end-get_e2m

	fmt.Println("\n############################")
	fmt.Println("################# Replace E2M ############")
	fmt.Println("#########################################")
	// begin-replace_e2m
	replaceE2mOptions := &logsv0.ReplaceE2mOptions{
		ID:                    core.StringPtr(event2MetricsID),
		Event2MetricPrototype: event2MetricPrototypeModel,
	}

	event2MetricResponse, detailedResponse, err := logsService.ReplaceE2m(replaceE2mOptions)
	if err != nil {
		fmt.Println("Error replacing e2m:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	fmt.Println("\n#Print E2M Response")
	fmt.Println("event2MetricResponse:", event2MetricResponse)

	// end-replace_e2m

	fmt.Println("\n############################")
	fmt.Println("################# Delete E2M ############")
	fmt.Println("#########################################")

	// begin-delete_e2m
	deleteE2mOptions := &logsv0.DeleteE2mOptions{
		ID: core.StringPtr(event2MetricsID),
	}

	detailedResponse, err = logsService.DeleteE2m(deleteE2mOptions)
	if err != nil {
		fmt.Println("Error deleting e2m:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	fmt.Println("\nsuccessfully deleted e2m", event2MetricsID)
	// end-delete_e2m

	fmt.Println("\n############################")
	fmt.Println("################# Create Rule Group ############")
	fmt.Println("#########################################")

	// begin - create_rule_group

	createRuleGroupOptions := &logsv0.CreateRuleGroupOptions{
		Name:        core.StringPtr(getRandomName()),
		Description: core.StringPtr("description"),
		Enabled:     core.BoolPtr(true),
		RuleMatchers: []logsv0.RulesV1RuleMatcherIntf{&logsv0.RulesV1RuleMatcherConstraintSubsystemName{
			SubsystemName: &logsv0.RulesV1SubsystemNameConstraint{
				Value: core.StringPtr("mysql"),
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

	ruleGroup, detailedResponse, err := logsService.CreateRuleGroup(createRuleGroupOptions)
	if err != nil {
		fmt.Println("Error creating rulegroups:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	// Print Rule Group ID
	fmt.Println("\nruleGroup ID :", *ruleGroup.ID)

	// end-create_rule_group

	fmt.Println("\n############################")
	fmt.Println("################# Update Rule Group ############")
	fmt.Println("#########################################")

	// begin-update_rule_group

	updateRuleGroupOptions := &logsv0.UpdateRuleGroupOptions{
		GroupID:     ruleGroup.ID,
		Name:        core.StringPtr(*ruleGroup.Name),
		Description: core.StringPtr("mysql audit updated logs parser"),
		Enabled:     core.BoolPtr(true),
		RuleMatchers: []logsv0.RulesV1RuleMatcherIntf{&logsv0.RulesV1RuleMatcherConstraintSubsystemName{
			SubsystemName: &logsv0.RulesV1SubsystemNameConstraint{
				Value: core.StringPtr("mysql"),
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
	}

	ruleGroup, detailedResponse, err = logsService.UpdateRuleGroup(updateRuleGroupOptions)
	if err != nil {
		fmt.Println("Error updating Rule Group:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	fmt.Println("\nRule Group:", *ruleGroup)

	// end-update_rule_group

	fmt.Println("\n############################")
	fmt.Println("################# Get Rule Group ############")
	fmt.Println("#########################################")

	// begin-get_rule_group

	getRuleGroupOptions := &logsv0.GetRuleGroupOptions{
		GroupID: ruleGroup.ID,
	}

	ruleGroup, detailedResponse, err = logsService.GetRuleGroup(getRuleGroupOptions)
	if err != nil {
		fmt.Println("Error getting rule group:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	// Print the result.
	ruleGroupResponse, err := json.MarshalIndent(ruleGroup, "", "    ")
	if err != nil {
		log.Fatalf("Error occurred during marshaling. Error: %s", err.Error())
	}
	fmt.Println("\n#Print Get Rule Group Response")
	fmt.Println("RuleGroup:", string(ruleGroupResponse))
	// end-get_rule_group

	fmt.Println("\n############################")
	fmt.Println("################# List Rule Groups ############")
	fmt.Println("#########################################")

	// begin-list_rule_groups

	listRuleGroupsOptions := &logsv0.ListRuleGroupsOptions{}

	ruleGroupCollection, response, err := logsService.ListRuleGroups(listRuleGroupsOptions)
	if err != nil {
		fmt.Println("Error getting rule group:", err)
		fmt.Println("Detailed response:", response)
		return
	}

	ruleGroupCollectionResponse, err := json.MarshalIndent(ruleGroupCollection, "", "    ")
	if err != nil {
		log.Fatalf("Error occurred during marshaling. Error: %s", err.Error())
	}

	fmt.Println("\n#Print List Rule Groups Response")
	fmt.Println("RuleGroup:", string(ruleGroupCollectionResponse))
	// end-list_rule_groups

	fmt.Println("\n############################")
	fmt.Println("################# Delete Rule Group ############")
	fmt.Println("#########################################")

	// begin-delete_rule_group

	deleteRuleGroupOptions := &logsv0.DeleteRuleGroupOptions{
		GroupID: ruleGroup.ID,
	}

	detailedResponse, err = logsService.DeleteRuleGroup(deleteRuleGroupOptions)
	if err != nil {
		fmt.Println("Error deleting rule group:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	// end-delete_rule_group

	fmt.Println("\nsuccessfully deleted rule group", *ruleGroup.ID)

	fmt.Println("\n############################")
	fmt.Println("################# Create Policy ############")
	fmt.Println("#########################################")
	// begin-create_policy

	qoutaRuleModel := &logsv0.QuotaV1Rule{
		RuleTypeID: core.StringPtr("is"),
		Name:       core.StringPtr("app"),
	}

	quotaV1LogRulesModel := &logsv0.QuotaV1LogRules{
		Severities: []string{"debug"},
	}

	policyPrototypeModel := &logsv0.PolicyPrototypeQuotaV1CreatePolicyRequestSourceTypeRulesLogRules{
		Name:            core.StringPtr(getRandomName()),
		Description:     core.StringPtr("description updated"),
		Priority:        core.StringPtr("type_medium"),
		ApplicationRule: qoutaRuleModel,
		SubsystemRule:   qoutaRuleModel,
		LogRules:        quotaV1LogRulesModel,
	}

	createPolicyOptions := &logsv0.CreatePolicyOptions{
		PolicyPrototype: policyPrototypeModel,
	}

	policy, detailedResponse, err := logsService.CreatePolicy(createPolicyOptions)
	if err != nil {
		fmt.Println("Error creating policy:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	var policyID *strfmt.UUID
	p, ok := policy.(*logsv0.Policy)
	if ok {
		policyID = p.ID
	}

	// Print Policy ID
	fmt.Println("\nPolicy ID :", policyID)
	// end-create_policy

	fmt.Println("\n############################")
	fmt.Println("################# Update Policy ############")
	fmt.Println("#########################################")
	// begin-update_policy

	updatePolicyOptions := &logsv0.UpdatePolicyOptions{
		ID:              policyID,
		PolicyPrototype: policyPrototypeModel,
	}

	policy, detailedResponse, err = logsService.UpdatePolicy(updatePolicyOptions)
	if err != nil {
		fmt.Println("Error updating Policy:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	fmt.Println("\nPolicy:", policy)

	fmt.Println("\n############################")
	fmt.Println("################# Get Policy ############")
	fmt.Println("#########################################")

	getPolicyOptions := &logsv0.GetPolicyOptions{
		ID: policyID,
	}

	policy, detailedResponse, err = logsService.GetPolicy(getPolicyOptions)
	if err != nil {
		fmt.Println("Error getting policy:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	// Print the result.
	policyDetails, err := json.MarshalIndent(policy, "", "    ")
	if err != nil {
		log.Fatalf("Error occurred during marshaling. Error: %s", err.Error())
	}
	fmt.Println("\n#Print Get Policy Response")
	fmt.Println("Policy:", string(policyDetails))
	// end-update_policy

	fmt.Println("\n############################")
	fmt.Println("################# Get Company Policies ############")
	fmt.Println("#########################################")
	// begin-get_company_policies

	getCompanyPoliciesOptions := &logsv0.GetCompanyPoliciesOptions{
		EnabledOnly: core.BoolPtr(true),
		SourceType:  core.StringPtr("logs"),
	}

	policyCollection, detailedResponse, err := logsService.GetCompanyPolicies(getCompanyPoliciesOptions)
	if err != nil {
		fmt.Println("Error getting company policies:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	fmt.Println("\n#Print Get Company Policies Response")
	fmt.Println("Policy Collection:", policyCollection)
	// end-get_company_policies

	fmt.Println("\n############################")
	fmt.Println("################# Delete Policy ############")
	fmt.Println("#########################################")
	// begin-delete_policy

	deletePolicyOptions := &logsv0.DeletePolicyOptions{
		ID: policyID,
	}

	detailedResponse, err = logsService.DeletePolicy(deletePolicyOptions)
	if err != nil {
		fmt.Println("Error deleting Policy:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	fmt.Println("\nsuccessfully deleted Policy", policyID)
	// end-delete_policy

	fmt.Println("################# Create Dashboard ############")
	fmt.Println("#########################################")
	// begin-create_dashboard
	apisDashboardsV1UUIDModel := &logsv0.ApisDashboardsV1UUID{
		Value: CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
	}

	apisDashboardsV1AstRowAppearanceModel := &logsv0.ApisDashboardsV1AstRowAppearance{
		Height: core.Int64Ptr(int64(5)),
	}

	apisDashboardsV1AstWidgetsCommonLegendModel := &logsv0.ApisDashboardsV1AstWidgetsCommonLegend{
		IsVisible:    core.BoolPtr(true),
		Columns:      []string{"unspecified"},
		GroupByQuery: core.BoolPtr(true),
	}

	apisDashboardsV1AstWidgetsLineChartTooltipModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartTooltip{
		ShowLabels: core.BoolPtr(true),
		Type:       core.StringPtr("unspecified"),
	}

	apisDashboardsV1AstWidgetsCommonLuceneQueryModel := &logsv0.ApisDashboardsV1AstWidgetsCommonLuceneQuery{
		Value: core.StringPtr(`coralogix.metadata.applicationName:"production"`),
	}

	apisDashboardsV1CommonLogsAggregationCountModel := &logsv0.ApisDashboardsV1CommonLogsAggregationCountEmpty{}

	apisDashboardsV1CommonLogsAggregationModel := &logsv0.ApisDashboardsV1CommonLogsAggregationValueCount{
		Count: apisDashboardsV1CommonLogsAggregationCountModel,
	}

	apisDashboardsV1AstFilterEqualsSelectionAllSelectionModel := &logsv0.ApisDashboardsV1AstFilterEqualsSelectionAllSelectionEmpty{}

	apisDashboardsV1AstFilterEqualsSelectionModel := &logsv0.ApisDashboardsV1AstFilterEqualsSelectionValueAll{
		All: apisDashboardsV1AstFilterEqualsSelectionAllSelectionModel,
	}

	apisDashboardsV1AstFilterEqualsModel := &logsv0.ApisDashboardsV1AstFilterEquals{
		Selection: apisDashboardsV1AstFilterEqualsSelectionModel,
	}

	apisDashboardsV1AstFilterOperatorModel := &logsv0.ApisDashboardsV1AstFilterOperatorValueEquals{
		Equals: apisDashboardsV1AstFilterEqualsModel,
	}

	apisDashboardsV1CommonObservationFieldModel := &logsv0.ApisDashboardsV1CommonObservationField{
		Keypath: []string{"testString"},
		Scope:   core.StringPtr("user_data"),
	}

	apisDashboardsV1AstFilterLogsFilterModel := &logsv0.ApisDashboardsV1AstFilterLogsFilter{
		Operator:         apisDashboardsV1AstFilterOperatorModel,
		ObservationField: apisDashboardsV1CommonObservationFieldModel,
	}

	apisDashboardsV1AstWidgetsLineChartLogsQueryModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartLogsQuery{
		LuceneQuery:  apisDashboardsV1AstWidgetsCommonLuceneQueryModel,
		GroupBy:      []string{"testString"},
		Aggregations: []logsv0.ApisDashboardsV1CommonLogsAggregationIntf{apisDashboardsV1CommonLogsAggregationModel},
		Filters:      []logsv0.ApisDashboardsV1AstFilterLogsFilter{*apisDashboardsV1AstFilterLogsFilterModel},
		GroupBys:     []logsv0.ApisDashboardsV1CommonObservationField{*apisDashboardsV1CommonObservationFieldModel},
	}

	apisDashboardsV1AstWidgetsLineChartQueryModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartQueryValueLogs{
		Logs: apisDashboardsV1AstWidgetsLineChartLogsQueryModel,
	}

	apisDashboardsV1AstWidgetsLineChartResolutionModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartResolution{
		BucketsPresented: core.Int64Ptr(int64(100)),
	}

	apisDashboardsV1AstWidgetsLineChartQueryDefinitionModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartQueryDefinition{
		ID:                 CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
		Query:              apisDashboardsV1AstWidgetsLineChartQueryModel,
		SeriesNameTemplate: core.StringPtr("{{severity}}"),
		SeriesCountLimit:   core.StringPtr("10"),
		Unit:               core.StringPtr("unspecified"),
		ScaleType:          core.StringPtr("unspecified"),
		Name:               core.StringPtr("CPU usage"),
		IsVisible:          core.BoolPtr(true),
		ColorScheme:        core.StringPtr("classic"),
		Resolution:         apisDashboardsV1AstWidgetsLineChartResolutionModel,
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

	apisDashboardsV1AstWidgetModel := &logsv0.ApisDashboardsV1AstWidget{
		ID:          apisDashboardsV1UUIDModel,
		Title:       core.StringPtr("Response time"),
		Description: core.StringPtr("The average response time of the system"),
		Definition:  apisDashboardsV1AstWidgetDefinitionModel,
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

	apisDashboardsV1AstMultiSelectLogsPathSourceModel := &logsv0.ApisDashboardsV1AstMultiSelectLogsPathSource{
		ObservationField: apisDashboardsV1CommonObservationFieldModel,
	}

	apisDashboardsV1AstMultiSelectSourceModel := &logsv0.ApisDashboardsV1AstMultiSelectSourceValueLogsPath{
		LogsPath: apisDashboardsV1AstMultiSelectLogsPathSourceModel,
	}

	apisDashboardsV1AstMultiSelectSelectionAllSelectionModel := &logsv0.ApisDashboardsV1AstMultiSelectSelectionAllSelectionEmpty{}

	apisDashboardsV1AstMultiSelectSelectionModel := &logsv0.ApisDashboardsV1AstMultiSelectSelectionValueAll{
		All: apisDashboardsV1AstMultiSelectSelectionAllSelectionModel,
	}

	apisDashboardsV1AstMultiSelectModel := &logsv0.ApisDashboardsV1AstMultiSelect{
		Source:               apisDashboardsV1AstMultiSelectSourceModel,
		Selection:            apisDashboardsV1AstMultiSelectSelectionModel,
		ValuesOrderDirection: core.StringPtr("asc"),
	}

	apisDashboardsV1AstVariableDefinitionModel := &logsv0.ApisDashboardsV1AstVariableDefinitionValueMultiSelect{
		MultiSelect: apisDashboardsV1AstMultiSelectModel,
	}

	apisDashboardsV1AstVariableModel := &logsv0.ApisDashboardsV1AstVariable{
		Name:        core.StringPtr("service_name"),
		Definition:  apisDashboardsV1AstVariableDefinitionModel,
		DisplayName: core.StringPtr("Service Name"),
	}

	apisDashboardsV1AstFilterSourceModel := &logsv0.ApisDashboardsV1AstFilterSourceValueLogs{
		Logs: apisDashboardsV1AstFilterLogsFilterModel,
	}

	apisDashboardsV1AstFilterModel := &logsv0.ApisDashboardsV1AstFilter{
		Source:    apisDashboardsV1AstFilterSourceModel,
		Enabled:   core.BoolPtr(true),
		Collapsed: core.BoolPtr(true),
	}

	apisDashboardsV1CommonPromQlQueryModel := &logsv0.ApisDashboardsV1CommonPromQlQuery{
		Value: core.StringPtr("sum(up)"),
	}

	apisDashboardsV1AstAnnotationMetricsSourceStartTimeMetricModel := &logsv0.ApisDashboardsV1AstAnnotationMetricsSourceStartTimeMetricEmpty{}

	apisDashboardsV1AstAnnotationMetricsSourceStrategyModel := &logsv0.ApisDashboardsV1AstAnnotationMetricsSourceStrategy{
		StartTimeMetric: apisDashboardsV1AstAnnotationMetricsSourceStartTimeMetricModel,
	}

	apisDashboardsV1AstAnnotationMetricsSourceModel := &logsv0.ApisDashboardsV1AstAnnotationMetricsSource{
		PromqlQuery:     apisDashboardsV1CommonPromQlQueryModel,
		Strategy:        apisDashboardsV1AstAnnotationMetricsSourceStrategyModel,
		MessageTemplate: core.StringPtr("testString"),
		Labels:          []string{"testString"},
	}

	apisDashboardsV1AstAnnotationSourceModel := &logsv0.ApisDashboardsV1AstAnnotationSourceValueMetrics{
		Metrics: apisDashboardsV1AstAnnotationMetricsSourceModel,
	}

	apisDashboardsV1AstAnnotationModel := &logsv0.ApisDashboardsV1AstAnnotation{
		ID:      CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
		Name:    core.StringPtr("Deployments"),
		Enabled: core.BoolPtr(true),
		Source:  apisDashboardsV1AstAnnotationSourceModel,
	}

	apisDashboardsV1CommonTimeFrameModel := &logsv0.ApisDashboardsV1CommonTimeFrame{
		From: CreateDateTime("2019-01-01T12:00:00.000Z"),
		To:   CreateDateTime("2019-01-01T12:00:00.000Z"),
	}

	dashboardModel := &logsv0.DashboardApisDashboardsV1AstDashboardTimeFrameAbsoluteTimeFrame{
		ID:                core.StringPtr("9U1Q8Hpa263Se8PkRKaiC"),
		Name:              core.StringPtr("My Dashboard"),
		Description:       core.StringPtr("This dashboard shows the performance of our production environment."),
		Layout:            apisDashboardsV1AstLayoutModel,
		Variables:         []logsv0.ApisDashboardsV1AstVariable{*apisDashboardsV1AstVariableModel},
		Filters:           []logsv0.ApisDashboardsV1AstFilter{*apisDashboardsV1AstFilterModel},
		Annotations:       []logsv0.ApisDashboardsV1AstAnnotation{*apisDashboardsV1AstAnnotationModel},
		AbsoluteTimeFrame: apisDashboardsV1CommonTimeFrameModel,
	}

	createDashboardOptions := &logsv0.CreateDashboardOptions{
		Dashboard: dashboardModel,
	}

	dashboard, detailedResponse, err := logsService.CreateDashboard(createDashboardOptions)
	if err != nil {
		fmt.Println("Error creating dashboard:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	var dashboardID string
	d, ok := dashboard.(*logsv0.Dashboard)
	if ok {
		dashboardID = *d.ID
	}

	// Print Dashboard ID
	fmt.Println("\nDashboard ID :", dashboardID)
	// end-create_dashboard

	fmt.Println("\n############################")
	fmt.Println("################# Replace Dashboard ############")
	fmt.Println("#########################################")
	// begin-replace_dashboard

	dashboardModelReplace := &logsv0.DashboardApisDashboardsV1AstDashboardTimeFrameAbsoluteTimeFrame{
		ID:                core.StringPtr("9U1Q8Hpa263Se8PkRKaiC"),
		Name:              core.StringPtr("My Dashboard"),
		Description:       core.StringPtr("This dashboard shows the performance of our production environment."),
		Layout:            apisDashboardsV1AstLayoutModel,
		Variables:         []logsv0.ApisDashboardsV1AstVariable{*apisDashboardsV1AstVariableModel},
		Filters:           []logsv0.ApisDashboardsV1AstFilter{*apisDashboardsV1AstFilterModel},
		Annotations:       []logsv0.ApisDashboardsV1AstAnnotation{*apisDashboardsV1AstAnnotationModel},
		AbsoluteTimeFrame: apisDashboardsV1CommonTimeFrameModel,
	}

	replaceDashboardOptions := &logsv0.ReplaceDashboardOptions{
		DashboardID: core.StringPtr(dashboardID),
		Dashboard:   dashboardModelReplace,
	}

	dashboardResponse, detailedResponse, err := logsService.ReplaceDashboard(replaceDashboardOptions)
	if err != nil {
		fmt.Println("Error replacing dashboard:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	fmt.Println("\n#Print replace dashboard Response")
	fmt.Println("Dashboard Response:", dashboardResponse)
	// end-replace_dashboard

	fmt.Println("\n############################")
	fmt.Println("################# Get Dashboard ############")
	fmt.Println("#########################################")
	// begin-get_dashboard

	getDashboardOptions := &logsv0.GetDashboardOptions{
		DashboardID: core.StringPtr(dashboardID),
	}

	dashboard, detailedResponse, err = logsService.GetDashboard(getDashboardOptions)
	if err != nil {
		fmt.Println("Error getting dashboard:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	// Print the result.
	dashboardDetails, err := json.MarshalIndent(dashboard, "", "    ")
	if err != nil {
		log.Fatalf("Error occurred during marshaling. Error: %s", err.Error())
	}
	fmt.Println("\n#Print Get Dashboard Response")
	fmt.Println("Dashboard:", string(dashboardDetails))
	// end-get_dashboard

	fmt.Println("\n############################")
	fmt.Println("################# Delete Dashboard ############")
	fmt.Println("#########################################")
	// begin-delete_dashboard

	deleteDashboardOptions := &logsv0.DeleteDashboardOptions{
		DashboardID: core.StringPtr(dashboardID),
	}

	detailedResponse, err = logsService.DeleteDashboard(deleteDashboardOptions)
	if err != nil {
		fmt.Println("Error deleting Dashboard:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	fmt.Println("\nsuccessfully deleted Dashboard", dashboardID)
	// end-delete_dashboard

	fmt.Println("\n############################")
	fmt.Println("################# Create Outgoing Webhook ############")
	fmt.Println("#########################################")
	// begin-create_outgoing_webhook

	outgoingWebhooksV1IbmEventNotificationsConfigModel := &logsv0.OutgoingWebhooksV1IbmEventNotificationsConfig{
		RegionID:                     core.StringPtr("us-south"),
		EventNotificationsInstanceID: CreateMockUUID("6964e1e9-74a2-4c6c-980b-d806ff75175d"),
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
	if err != nil {
		fmt.Println("Error creating outgoing webhook:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	var outgoingWebhookID *strfmt.UUID
	ow, ok := outgoingWebhook.(*logsv0.OutgoingWebhook)
	fmt.Println("OW", ow)
	if ok {
		outgoingWebhookID = ow.ID
	}

	// Print outgoingWebhook ID
	fmt.Println("\nOutgoingWebhook ID :", outgoingWebhookID)
	// end-create_outgoing_webhook

	fmt.Println("\n############################")
	fmt.Println("################# Update Outgoing Webhook ############")
	fmt.Println("#########################################")
	// begin-update_outgoing_webhook

	outgoingWebhooksV1IbmEventNotificationsConfigModel1 := &logsv0.OutgoingWebhooksV1IbmEventNotificationsConfig{
		RegionID:                     core.StringPtr("us-south"),
		EventNotificationsInstanceID: CreateMockUUID("6964e1e9-74a2-4c6c-980b-d806ff75175d"),
	}

	outgoingWebhookPrototypeModel1 := &logsv0.OutgoingWebhookPrototypeOutgoingWebhooksV1OutgoingWebhookInputDataConfigIbmEventNotifications{
		Type:                  core.StringPtr("ibm_event_notifications"),
		Name:                  core.StringPtr("test-webhook"),
		URL:                   core.StringPtr("testString"),
		IbmEventNotifications: outgoingWebhooksV1IbmEventNotificationsConfigModel1,
	}

	updateOutgoingWebhookOptions := &logsv0.UpdateOutgoingWebhookOptions{
		ID:                       outgoingWebhookID,
		OutgoingWebhookPrototype: outgoingWebhookPrototypeModel1,
	}

	outgoingWebhook, detailedResponse, err = logsService.UpdateOutgoingWebhook(updateOutgoingWebhookOptions)
	if err != nil {
		fmt.Println("Error updating Outgoing Webhook:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	fmt.Println("\nOutgoing Webhook:", outgoingWebhook)
	// end-update_outgoing_webhook

	fmt.Println("\n############################")
	fmt.Println("################# List Outgoing Webhook ############")
	fmt.Println("#########################################")
	// begin-list_outgoing_webhooks
	listOutgoingWebhooksOptions := &logsv0.ListOutgoingWebhooksOptions{
		Type: core.StringPtr("ibm_event_notifications"),
	}

	outgoingWebhookCollection, detailedResponse, err := logsService.ListOutgoingWebhooks(listOutgoingWebhooksOptions)
	if err != nil {
		fmt.Println("Error getting outgoing Webhook Collection:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	owList, err := json.MarshalIndent(outgoingWebhookCollection, "", "    ")
	if err != nil {
		log.Fatalf("Error occurred during marshaling. Error: %s", err.Error())
	}
	fmt.Println("\n#Print List Outgoing Webhook Response")
	fmt.Println("OutgoingWebhookCollection:", string(owList))
	// end-list_outgoing_webhooks

	fmt.Println("\n############################")
	fmt.Println("################# Get Outgoing Webhook ############")
	fmt.Println("#########################################")
	// begin-get_outgoing_webhook

	getOutgoingWebhookOptions := &logsv0.GetOutgoingWebhookOptions{
		ID: outgoingWebhookID,
	}

	outgoingWebhook, detailedResponse, err = logsService.GetOutgoingWebhook(getOutgoingWebhookOptions)
	if err != nil {
		fmt.Println("Error getting outgoingWebhook:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	// Print the result.
	outgoingWebhookDetails, err := json.MarshalIndent(outgoingWebhook, "", "    ")
	if err != nil {
		log.Fatalf("Error occurred during marshaling. Error: %s", err.Error())
	}
	fmt.Println("\n#Print Get Outgoing Webhook Response")
	fmt.Println("OutgoingWebhook:", string(outgoingWebhookDetails))
	// end-get_outgoing_webhook

	fmt.Println("\n############################")
	fmt.Println("################# Delete Outgoing Webhook ############")
	fmt.Println("#########################################")
	// begin-delete_outgoing_webhook

	deleteOutgoingWebhookOptions := &logsv0.DeleteOutgoingWebhookOptions{
		ID: outgoingWebhookID,
	}

	detailedResponse, err = logsService.DeleteOutgoingWebhook(deleteOutgoingWebhookOptions)
	if err != nil {
		fmt.Println("Error deleting Outgoing Webhook:", err)
		fmt.Println("Detailed response:", detailedResponse)
		return
	}

	fmt.Println("\nsuccessfully deleted Outgoing Webhook", outgoingWebhookID)
	// end-delete_outgoing_webhook

	fmt.Println("\n############################")
	fmt.Println("################# Create View Folder ############")
	fmt.Println("\n############################")
	// begin-create_view_folder

	createViewFolderOptions := &logsv0.CreateViewFolderOptions{
		Name: core.StringPtr("My Folder"),
	}

	viewFolder, response, err := logsService.CreateViewFolder(createViewFolderOptions)
	if err != nil {
		fmt.Println("Error creating view:", err)
		fmt.Println("Detailed response:", response)
		return
	}

	viewFolderPayload, err := json.MarshalIndent(viewFolder, "", "    ")
	if err != nil {
		log.Fatalf("Error occurred during marshaling. Error: %s", err.Error())
	}

	fmt.Println("\n#Print CREATE VIEW FOLDER")
	fmt.Println(string(viewFolderPayload))

	// end-create_view_folder

	fmt.Println("\n############################")
	fmt.Println("################# Get View Folder ############")
	fmt.Println("\n############################")
	// begin-get_view_folder

	getViewFolderOptions := &logsv0.GetViewFolderOptions{
		ID: viewFolder.ID,
	}

	viewFolder, response, err = logsService.GetViewFolder(getViewFolderOptions)
	if err != nil {
		fmt.Println("Error creating view:", err)
		fmt.Println("Detailed response:", response)
		return
	}

	viewFolderPayload, err = json.MarshalIndent(viewFolder, "", "    ")
	if err != nil {
		log.Fatalf("Error occurred during marshaling. Error: %s", err.Error())
	}

	fmt.Println("\n#Print GET VIEW FOLDER")
	fmt.Println(string(viewFolderPayload))

	// end-get_view_folder

	fmt.Println("\n############################")
	fmt.Println("################# List View Folder ############")
	fmt.Println("\n############################")
	// begin-list_view_folders

	listViewFoldersOptions := &logsv0.ListViewFoldersOptions{}

	viewFolderCollection, response, err := logsService.ListViewFolders(listViewFoldersOptions)
	if err != nil {
		fmt.Println("Error creating view:", err)
		fmt.Println("Detailed response:", response)
		return
	}

	viewFolderCollectionPayload, err := json.MarshalIndent(viewFolderCollection, "", "    ")
	if err != nil {
		log.Fatalf("Error occurred during marshaling. Error: %s", err.Error())
	}

	fmt.Println("\n#Print LIST VIEW FOLDER")
	fmt.Println(string(viewFolderCollectionPayload))

	// end-list_view_folders

	fmt.Println("\n############################")
	fmt.Println("################# Create View ############")
	fmt.Println("\n############################")
	// begin-create_view

	apisViewsV1SearchQueryModel := &logsv0.ApisViewsV1SearchQuery{
		Query: core.StringPtr("logs"),
	}

	apisViewsV1CustomTimeSelectionModel := &logsv0.ApisViewsV1CustomTimeSelection{
		FromTime: CreateDateTime("2024-01-25T11:31:43.152Z"),
		ToTime:   CreateDateTime("2024-01-25T11:37:13.238Z"),
	}

	apisViewsV1TimeSelectionModel := &logsv0.ApisViewsV1TimeSelectionSelectionTypeCustomSelection{
		CustomSelection: apisViewsV1CustomTimeSelectionModel,
	}

	apisViewsV1FilterModel := &logsv0.ApisViewsV1Filter{
		Name:           core.StringPtr("applicationName"),
		SelectedValues: map[string]bool{"key1": true},
	}

	apisViewsV1SelectedFiltersModel := &logsv0.ApisViewsV1SelectedFilters{
		Filters: []logsv0.ApisViewsV1Filter{*apisViewsV1FilterModel},
	}

	createViewOptions := &logsv0.CreateViewOptions{
		Name:          core.StringPtr("Logs view"),
		SearchQuery:   apisViewsV1SearchQueryModel,
		TimeSelection: apisViewsV1TimeSelectionModel,
		Filters:       apisViewsV1SelectedFiltersModel,
		FolderID:      viewFolder.ID,
	}

	view, response, err := logsService.CreateView(createViewOptions)
	if err != nil {
		fmt.Println("Error creating view:", err)
		fmt.Println("Detailed response:", response)
		return
	}

	viewPayload, err := json.MarshalIndent(view, "", "    ")
	if err != nil {
		log.Fatalf("Error occurred during marshaling. Error: %s", err.Error())
	}
	fmt.Println("\n#Print CREATE VIEW Payload")
	fmt.Println(string(viewPayload))
	// end-create_view

	fmt.Println("\n############################")
	fmt.Println("################# Get View ############")
	fmt.Println("\n############################")
	// begin-get_view

	getViewOptions := &logsv0.GetViewOptions{
		ID: core.Int64Ptr(*view.ID),
	}

	view, response, err = logsService.GetView(getViewOptions)
	if err != nil {
		fmt.Println("Error getting view:", err)
		fmt.Println("Detailed response:", response)
		return
	}

	viewPayload, err = json.MarshalIndent(view, "", "    ")
	if err != nil {
		log.Fatalf("Error occurred during marshaling. Error: %s", err.Error())
	}

	fmt.Println("\n#Print GET VIEW Payload")
	fmt.Println(string(viewPayload))
	// end-get_view

	fmt.Println("\n############################")
	fmt.Println("################# Replace View ############")
	fmt.Println("\n############################")
	// begin-replace_view

	replaceViewOptions := &logsv0.ReplaceViewOptions{
		ID:            core.Int64Ptr(*view.ID),
		Name:          core.StringPtr("Logs view"),
		SearchQuery:   apisViewsV1SearchQueryModel,
		TimeSelection: apisViewsV1TimeSelectionModel,
		Filters:       apisViewsV1SelectedFiltersModel,
		FolderID:      viewFolder.ID,
	}

	view, response, err = logsService.ReplaceView(replaceViewOptions)
	if err != nil {
		fmt.Println("Error replacing view:", err)
		fmt.Println("Detailed response:", response)
		return
	}

	viewPayload, err = json.MarshalIndent(view, "", "    ")
	if err != nil {
		log.Fatalf("Error occurred during marshaling. Error: %s", err.Error())
	}

	fmt.Println("\n#Print REPLACE VIEW Payload")
	fmt.Println(string(viewPayload))
	// end-replace_view

	fmt.Println("\n############################")
	fmt.Println("################# Delete View ############")
	fmt.Println("\n############################")
	// begin-delete_view

	deleteViewOptions := &logsv0.DeleteViewOptions{
		ID: core.Int64Ptr(*view.ID),
	}

	response, err = logsService.DeleteView(deleteViewOptions)
	if err != nil {
		fmt.Println("Error deleting view:", err)
		fmt.Println("Detailed response:", response)
		return
	}

	fmt.Println("Deleted view: ", *view.ID)
	// end-delete_view

	fmt.Println("\n############################")
	fmt.Println("################# Delete View Folder ############")
	fmt.Println("\n############################")
	// begin-delete_view_folder

	deleteViewFolderOptions := &logsv0.DeleteViewFolderOptions{
		ID: viewFolder.ID,
	}

	response, err = logsService.DeleteViewFolder(deleteViewFolderOptions)
	if err != nil {
		fmt.Println("Error deleting view folder:", err)
		fmt.Println("Detailed response:", response)
		return
	}

	fmt.Println("Deleted view folder: ", *view.ID)
	// end-delete_view_folder

	fmt.Println("\n############################")
	fmt.Println("################# Dataprime Query ############")
	fmt.Println("\n############################")
	// create-query

	queryOptions := logsv0.QueryOptions{
		Query: core.StringPtr("source logs | limit 10"),
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
	// end-query
}

type callBack struct{}

func (cb callBack) OnClose() {
	fmt.Println("closing callback")
}

func (cb callBack) OnKeepAlive() {
	fmt.Println("keepalive")
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

func CreateDateTime(mockData string) *strfmt.DateTime {
	d, err := core.ParseDateTime(mockData)
	if err != nil {
		return nil
	}
	return &d
}

func CreateMockUUID(mockData string) *strfmt.UUID {
	uuid := strfmt.UUID(mockData)
	return &uuid
}
