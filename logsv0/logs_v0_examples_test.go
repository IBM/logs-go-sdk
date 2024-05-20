//go:build examples

/**
 * (C) Copyright IBM Corp. 2024.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package logsv0_test

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/go-openapi/strfmt"
	"github.com/IBM/logs-go-sdk/logsv0"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// This file provides an example of how to use the logs service.
//
// The following configuration properties are assumed to be defined:
// LOGS_URL=<service base url>
// LOGS_AUTH_TYPE=iam
// LOGS_APIKEY=<IAM apikey>
// LOGS_AUTH_URL=<IAM token service base URL - omit this if using the production environment>
//
// These configuration properties can be exported as environment variables, or stored
// in a configuration file and then:
// export IBM_CREDENTIALS_FILE=<name of configuration file>
var _ = Describe(`LogsV0 Examples Tests`, func() {

	const externalConfigFile = "../logs.env"

	var (
		logsService *logsv0.LogsV0
		config      map[string]string

		// Variables to hold link values
		alertIdLink           strfmt.UUID
		dashboardIdLink       string
		events2MetricsIdLink  strfmt.UUID
		folderIdLink          strfmt.UUID
		outgoingWebhookIdLink strfmt.UUID
		policyIdLink          strfmt.UUID
		ruleGroupIdLink       strfmt.UUID
		viewFolderIdLink      strfmt.UUID
		viewIdLink            int64
	)

	var shouldSkipTest = func() {
		Skip("External configuration is not available, skipping examples...")
	}

	Describe(`External configuration`, func() {
		It("Successfully load the configuration", func() {
			var err error
			_, err = os.Stat(externalConfigFile)
			if err != nil {
				Skip("External configuration file not found, skipping examples: " + err.Error())
			}

			os.Setenv("IBM_CREDENTIALS_FILE", externalConfigFile)
			config, err = core.GetServiceProperties(logsv0.DefaultServiceName)
			if err != nil {
				Skip("Error loading service properties, skipping examples: " + err.Error())
			} else if len(config) == 0 {
				Skip("Unable to load service properties, skipping examples")
			}

			shouldSkipTest = func() {}
		})
	})

	Describe(`Client initialization`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It("Successfully construct the service client instance", func() {
			var err error

			// begin-common

			logsServiceOptions := &logsv0.LogsV0Options{}

			logsService, err = logsv0.NewLogsV0UsingExternalConfig(logsServiceOptions)

			if err != nil {
				panic(err)
			}

			// end-common

			Expect(logsService).ToNot(BeNil())
		})
	})

	Describe(`LogsV0 request examples`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateAlert request example`, func() {
			// Skip("External configuration is not available, skipping examples...")
			fmt.Println("\nCreateAlert() result:")
			// begin-create_alert

			alertsV2ConditionParametersModel := &logsv0.AlertsV2ConditionParameters{
				Threshold:         core.Float64Ptr(float64(1)),
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
			}

			alertsV1AlertFiltersMetadataFiltersModel := &logsv0.AlertsV1AlertFiltersMetadataFilters{}

			alertsV1AlertFiltersModel := &logsv0.AlertsV1AlertFilters{
				Severities: []string{"info"},
				Metadata:   alertsV1AlertFiltersMetadataFiltersModel,
				Text:       core.StringPtr("initiator.id.keyword:iam-ServiceId-10820fd6-c3fe-414e-8fd5-44ce95f7d34d AND action.keyword:cloud-object-storage.object.create"),
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

			alertsV1MetaLabelModel := &logsv0.AlertsV1MetaLabel{
				Key:   core.StringPtr("env"),
				Value: core.StringPtr("dev"),
			}

			alertsV2AlertIncidentSettingsModel := &logsv0.AlertsV2AlertIncidentSettings{
				RetriggeringPeriodSeconds: core.Int64Ptr(int64(300)),
				NotifyOn:                  core.StringPtr("triggered_only"),
				UseAsNotificationSettings: core.BoolPtr(true),
			}

			createAlertOptions := logsService.NewCreateAlertOptions(
				"Test alert",
				true,
				"info_or_unspecified",
				alertsV2AlertConditionModel,
				[]logsv0.AlertsV2AlertNotificationGroups{*alertsV2AlertNotificationGroupsModel},
				alertsV1AlertFiltersModel,
			)
			createAlertOptions.SetDescription("Alert if the number of logs reaches a threshold")
			createAlertOptions.SetActiveWhen(alertsV1AlertActiveWhenModel)
			createAlertOptions.SetMetaLabels([]logsv0.AlertsV1MetaLabel{*alertsV1MetaLabelModel})
			createAlertOptions.SetMetaLabelsStrings([]string{})
			createAlertOptions.SetIncidentSettings(alertsV2AlertIncidentSettingsModel)

			alert, response, err := logsService.CreateAlert(createAlertOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(alert, "", "  ")
			fmt.Println(string(b))

			// end-create_alert

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(alert).ToNot(BeNil())

			alertIdLink = *alert.ID
			fmt.Fprintf(GinkgoWriter, "Saved alertIdLink value: %v\n", alertIdLink)
		})
		It(`CreateRuleGroup request example`, func() {
			fmt.Println("\nCreateRuleGroup() result:")
			// begin-create_rule_group

			rulesV1ParseParametersModel := &logsv0.RulesV1ParseParameters{
				DestinationField: core.StringPtr("text"),
				Rule:             core.StringPtr("(?P<timestamp>[^,]+),(?P<hostname>[^,]+),(?P<username>[^,]+),(?P<ip>[^,]+),(?P<connectionId>[0-9]+),(?P<queryId>[0-9]+),(?P<operation>[^,]+),(?P<database>[^,]+),'?(?P<object>.*)'?,(?P<returnCode>[0-9]+)"),
			}

			rulesV1RuleParametersModel := &logsv0.RulesV1RuleParametersRuleParametersParseParameters{
				ParseParameters: rulesV1ParseParametersModel,
			}

			rulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRuleModel := &logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRule{
				Name:        core.StringPtr("mysql-parse"),
				Description: core.StringPtr("mysql-parse"),
				SourceField: core.StringPtr("text"),
				Parameters:  rulesV1RuleParametersModel,
				Enabled:     core.BoolPtr(true),
				Order:       core.Int64Ptr(int64(1)),
			}

			rulesV1CreateRuleGroupRequestCreateRuleSubgroupModel := &logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroup{
				Rules:   []logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRule{*rulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRuleModel},
				Enabled: core.BoolPtr(true),
				Order:   core.Int64Ptr(int64(1)),
			}

			rulesV1SubsystemNameConstraintModel := &logsv0.RulesV1SubsystemNameConstraint{
				Value: core.StringPtr("mysql"),
			}

			rulesV1RuleMatcherModel := &logsv0.RulesV1RuleMatcherConstraintSubsystemName{
				SubsystemName: rulesV1SubsystemNameConstraintModel,
			}

			createRuleGroupOptions := logsService.NewCreateRuleGroupOptions(
				"mysql-extractrule",
				[]logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroup{*rulesV1CreateRuleGroupRequestCreateRuleSubgroupModel},
			)
			createRuleGroupOptions.SetDescription("mysql audit logs  parser")
			createRuleGroupOptions.SetEnabled(true)
			createRuleGroupOptions.SetRuleMatchers([]logsv0.RulesV1RuleMatcherIntf{rulesV1RuleMatcherModel})
			createRuleGroupOptions.SetOrder(int64(39))

			ruleGroup, response, err := logsService.CreateRuleGroup(createRuleGroupOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(ruleGroup, "", "  ")
			fmt.Println(string(b))

			// end-create_rule_group

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(ruleGroup).ToNot(BeNil())

			ruleGroupIdLink = *ruleGroup.ID
			fmt.Fprintf(GinkgoWriter, "Saved ruleGroupIdLink value: %v\n", ruleGroupIdLink)
		})
		It(`CreateOutgoingWebhook request example`, func() {
			fmt.Println("\nCreateOutgoingWebhook() result:")
			// begin-create_outgoing_webhook

			outgoingWebhooksV1IbmEventNotificationsConfigModel := &logsv0.OutgoingWebhooksV1IbmEventNotificationsConfig{
				RegionID:                     core.StringPtr("us-south"),
				EventNotificationsInstanceID: CreateMockUUID("6964e1e9-74a2-4c6c-980b-d806ff75175d"),
			}

			outgoingWebhookPrototypeModel := &logsv0.OutgoingWebhookPrototypeOutgoingWebhooksV1OutgoingWebhookInputDataConfigIbmEventNotifications{
				Type:                  core.StringPtr("ibm_event_notifications"),
				Name:                  core.StringPtr("Event Notifications Integration"),
				IbmEventNotifications: outgoingWebhooksV1IbmEventNotificationsConfigModel,
			}

			createOutgoingWebhookOptions := logsService.NewCreateOutgoingWebhookOptions(
				outgoingWebhookPrototypeModel,
			)

			outgoingWebhook, response, err := logsService.CreateOutgoingWebhook(createOutgoingWebhookOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(outgoingWebhook, "", "  ")
			fmt.Println(string(b))

			// end-create_outgoing_webhook

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(outgoingWebhook).ToNot(BeNil())

			outgoingWebhookIdLink = *outgoingWebhook.(*logsv0.OutgoingWebhook).ID
			fmt.Fprintf(GinkgoWriter, "Saved outgoingWebhookIdLink value: %v\n", outgoingWebhookIdLink)
		})
		It(`CreatePolicy request example`, func() {
			fmt.Println("\nCreatePolicy() result:")
			// begin-create_policy

			quotaV1RuleModel := &logsv0.QuotaV1Rule{
				RuleTypeID: core.StringPtr("is"),
				Name:       core.StringPtr("policy-test"),
			}

			quotaV1LogRulesModel := &logsv0.QuotaV1LogRules{
				Severities: []string{"debug", "verbose", "info", "warning", "error"},
			}

			policyPrototypeModel := &logsv0.PolicyPrototypeQuotaV1CreatePolicyRequestSourceTypeRulesLogRules{
				Name:            core.StringPtr("Med_policy"),
				Description:     core.StringPtr("Medium Policy"),
				Priority:        core.StringPtr("type_high"),
				ApplicationRule: quotaV1RuleModel,
				SubsystemRule:   quotaV1RuleModel,
				LogRules:        quotaV1LogRulesModel,
			}

			createPolicyOptions := logsService.NewCreatePolicyOptions(
				policyPrototypeModel,
			)

			policy, response, err := logsService.CreatePolicy(createPolicyOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(policy, "", "  ")
			fmt.Println(string(b))

			// end-create_policy

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(policy).ToNot(BeNil())

			policyIdLink = *policy.(*logsv0.Policy).ID
			fmt.Fprintf(GinkgoWriter, "Saved policyIdLink value: %v\n", policyIdLink)
		})
		It(`CreateDashboard request example`, func() {
			fmt.Println("\nCreateDashboard() result:")
			// begin-create_dashboard

			apisDashboardsV1UUIDModel := &logsv0.ApisDashboardsV1UUID{
				Value: CreateMockUUID("10c27980-3532-21b0-8069-0c9110f03c90"),
			}

			apisDashboardsV1AstRowAppearanceModel := &logsv0.ApisDashboardsV1AstRowAppearance{
				Height: core.Int64Ptr(int64(19)),
			}

			apisDashboardsV1AstWidgetsCommonLegendModel := &logsv0.ApisDashboardsV1AstWidgetsCommonLegend{
				IsVisible:    core.BoolPtr(true),
				GroupByQuery: core.BoolPtr(true),
			}

			apisDashboardsV1AstWidgetsLineChartTooltipModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartTooltip{
				ShowLabels: core.BoolPtr(false),
				Type:       core.StringPtr("all"),
			}

			apisDashboardsV1AstWidgetsCommonPromQlQueryModel := &logsv0.ApisDashboardsV1AstWidgetsCommonPromQlQuery{
				Value: core.StringPtr("sum(rate(cx_data_usage_bytes_total[20m]))by(pillar,tier)"),
			}

			apisDashboardsV1AstWidgetsLineChartMetricsQueryModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartMetricsQuery{
				PromqlQuery: apisDashboardsV1AstWidgetsCommonPromQlQueryModel,
			}

			apisDashboardsV1AstWidgetsLineChartQueryModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartQueryValueMetrics{
				Metrics: apisDashboardsV1AstWidgetsLineChartMetricsQueryModel,
			}

			apisDashboardsV1AstWidgetsLineChartResolutionModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartResolution{
				BucketsPresented: core.Int64Ptr(int64(96)),
			}

			apisDashboardsV1AstWidgetsLineChartQueryDefinitionModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartQueryDefinition{
				ID:               CreateMockUUID("e4560525-521c-49e7-a7de-a2925626c304"),
				Query:            apisDashboardsV1AstWidgetsLineChartQueryModel,
				SeriesCountLimit: core.StringPtr("20"),
				ScaleType:        core.StringPtr("linear"),
				Name:             core.StringPtr("Query1"),
				IsVisible:        core.BoolPtr(true),
				ColorScheme:      core.StringPtr("classic"),
				Resolution:       apisDashboardsV1AstWidgetsLineChartResolutionModel,
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
				ID:         apisDashboardsV1UUIDModel,
				Title:      core.StringPtr("Size"),
				Definition: apisDashboardsV1AstWidgetDefinitionModel,
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

			apisDashboardsV1AstFilterEqualsSelectionListSelectionModel := &logsv0.ApisDashboardsV1AstFilterEqualsSelectionListSelection{}

			apisDashboardsV1AstFilterEqualsSelectionModel := &logsv0.ApisDashboardsV1AstFilterEqualsSelectionValueList{
				List: apisDashboardsV1AstFilterEqualsSelectionListSelectionModel,
			}

			apisDashboardsV1AstFilterEqualsModel := &logsv0.ApisDashboardsV1AstFilterEquals{
				Selection: apisDashboardsV1AstFilterEqualsSelectionModel,
			}

			apisDashboardsV1AstFilterOperatorModel := &logsv0.ApisDashboardsV1AstFilterOperatorValueEquals{
				Equals: apisDashboardsV1AstFilterEqualsModel,
			}

			apisDashboardsV1CommonObservationFieldModel := &logsv0.ApisDashboardsV1CommonObservationField{
				Keypath: []string{"applicationname"},
				Scope:   core.StringPtr("label"),
			}

			apisDashboardsV1AstFilterLogsFilterModel := &logsv0.ApisDashboardsV1AstFilterLogsFilter{
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

			dashboardModel := &logsv0.DashboardApisDashboardsV1AstDashboardTimeFrameRelativeTimeFrame{
				Name:              core.StringPtr("DataUsageToMetrics Dashboard"),
				Layout:            apisDashboardsV1AstLayoutModel,
				Filters:           []logsv0.ApisDashboardsV1AstFilter{*apisDashboardsV1AstFilterModel},
				RelativeTimeFrame: core.StringPtr("86400s"),
			}

			createDashboardOptions := logsService.NewCreateDashboardOptions(
				dashboardModel,
			)

			dashboard, response, err := logsService.CreateDashboard(createDashboardOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(dashboard, "", "  ")
			fmt.Println(string(b))

			// end-create_dashboard

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(dashboard).ToNot(BeNil())

			dashboardIdLink = *dashboard.(*logsv0.Dashboard).ID
			fmt.Fprintf(GinkgoWriter, "Saved dashboardIdLink value: %v\n", dashboardIdLink)
		})
		It(`CreateDashboardFolder request example`, func() {
			fmt.Println("\nCreateDashboardFolder() result:")
			// begin-create_dashboard_folder

			createDashboardFolderOptions := logsService.NewCreateDashboardFolderOptions(
				"My Folder",
			)

			dashboardFolder, response, err := logsService.CreateDashboardFolder(createDashboardFolderOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(dashboardFolder, "", "  ")
			fmt.Println(string(b))

			// end-create_dashboard_folder

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(dashboardFolder).ToNot(BeNil())

			folderIdLink = *dashboardFolder.ID
			fmt.Fprintf(GinkgoWriter, "Saved folderIdLink value: %v\n", folderIdLink)
		})
		It(`CreateE2m request example`, func() {
			fmt.Println("\nCreateE2m() result:")
			// begin-create_e2m

			apisLogs2metricsV2LogsQueryModel := &logsv0.ApisLogs2metricsV2LogsQuery{
				Lucene: core.StringPtr("logs"),
			}

			event2MetricPrototypeModel := &logsv0.Event2MetricPrototypeApisEvents2metricsV2E2mCreateParamsQueryLogsQuery{
				Name:              core.StringPtr("test em2"),
				Description:       core.StringPtr("Test e2m"),
				PermutationsLimit: core.Int64Ptr(int64(1)),
				Type:              core.StringPtr("logs2metrics"),
				LogsQuery:         apisLogs2metricsV2LogsQueryModel,
			}

			createE2mOptions := logsService.NewCreateE2mOptions(
				event2MetricPrototypeModel,
			)

			event2Metric, response, err := logsService.CreateE2m(createE2mOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(event2Metric, "", "  ")
			fmt.Println(string(b))

			// end-create_e2m

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(event2Metric).ToNot(BeNil())

			events2MetricsIdLink = *event2Metric.(*logsv0.Event2Metric).ID
			fmt.Fprintf(GinkgoWriter, "Saved events2MetricsIdLink value: %v\n", events2MetricsIdLink)
		})
		It(`CreateView request example`, func() {
			fmt.Println("\nCreateView() result:")
			// begin-create_view

			apisViewsV1SearchQueryModel := &logsv0.ApisViewsV1SearchQuery{
				Query: core.StringPtr("logs"),
			}

			apisViewsV1CustomTimeSelectionModel := &logsv0.ApisViewsV1CustomTimeSelection{
				FromTime: CreateMockDateTime("2024-01-25T11:31:43.152Z"),
				ToTime:   CreateMockDateTime("2024-01-25T11:37:13.238Z"),
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

			createViewOptions := logsService.NewCreateViewOptions(
				"Logs view",
				apisViewsV1SearchQueryModel,
				apisViewsV1TimeSelectionModel,
			)
			createViewOptions.SetFilters(apisViewsV1SelectedFiltersModel)

			view, response, err := logsService.CreateView(createViewOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(view, "", "  ")
			fmt.Println(string(b))

			// end-create_view

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(view).ToNot(BeNil())

			viewIdLink = *view.ID
			fmt.Fprintf(GinkgoWriter, "Saved viewIdLink value: %v\n", viewIdLink)
		})
		It(`CreateViewFolder request example`, func() {
			fmt.Println("\nCreateViewFolder() result:")
			// begin-create_view_folder

			createViewFolderOptions := logsService.NewCreateViewFolderOptions(
				"My Folder",
			)

			viewFolder, response, err := logsService.CreateViewFolder(createViewFolderOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(viewFolder, "", "  ")
			fmt.Println(string(b))

			// end-create_view_folder

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(viewFolder).ToNot(BeNil())

			viewFolderIdLink = *viewFolder.ID
			fmt.Fprintf(GinkgoWriter, "Saved viewFolderIdLink value: %v\n", viewFolderIdLink)
		})
		It(`GetAlert request example`, func() {
			fmt.Println("\nGetAlert() result:")
			// begin-get_alert

			getAlertOptions := logsService.NewGetAlertOptions(
				&alertIdLink,
			)

			alert, response, err := logsService.GetAlert(getAlertOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(alert, "", "  ")
			fmt.Println(string(b))

			// end-get_alert

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(alert).ToNot(BeNil())
		})
		It(`UpdateAlert request example`, func() {
			fmt.Println("\nUpdateAlert() result:")
			// begin-update_alert

			alertsV2ConditionParametersModel := &logsv0.AlertsV2ConditionParameters{
				Threshold:         core.Float64Ptr(float64(1)),
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
			}

			alertsV1AlertFiltersMetadataFiltersModel := &logsv0.AlertsV1AlertFiltersMetadataFilters{}

			alertsV1AlertFiltersModel := &logsv0.AlertsV1AlertFilters{
				Severities: []string{"info"},
				Metadata:   alertsV1AlertFiltersMetadataFiltersModel,
				Text:       core.StringPtr("initiator.id.keyword:iam-ServiceId-10820fd6-c3fe-414e-8fd5-44ce95f7d34d AND action.keyword:cloud-object-storage.object.create"),
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

			alertsV1MetaLabelModel := &logsv0.AlertsV1MetaLabel{
				Key:   core.StringPtr("env"),
				Value: core.StringPtr("dev"),
			}

			alertsV2AlertIncidentSettingsModel := &logsv0.AlertsV2AlertIncidentSettings{
				RetriggeringPeriodSeconds: core.Int64Ptr(int64(300)),
				NotifyOn:                  core.StringPtr("triggered_only"),
				UseAsNotificationSettings: core.BoolPtr(true),
			}

			updateAlertOptions := logsService.NewUpdateAlertOptions(
				&alertIdLink,
				"Test alert",
				true,
				"info_or_unspecified",
				alertsV2AlertConditionModel,
				[]logsv0.AlertsV2AlertNotificationGroups{*alertsV2AlertNotificationGroupsModel},
				alertsV1AlertFiltersModel,
			)
			updateAlertOptions.SetDescription("Alert if the number of logs reaches a threshold")
			updateAlertOptions.SetActiveWhen(alertsV1AlertActiveWhenModel)
			updateAlertOptions.SetMetaLabels([]logsv0.AlertsV1MetaLabel{*alertsV1MetaLabelModel})
			updateAlertOptions.SetMetaLabelsStrings([]string{})
			updateAlertOptions.SetIncidentSettings(alertsV2AlertIncidentSettingsModel)

			alert, response, err := logsService.UpdateAlert(updateAlertOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(alert, "", "  ")
			fmt.Println(string(b))

			// end-update_alert

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(alert).ToNot(BeNil())
		})
		It(`GetAlerts request example`, func() {
			fmt.Println("\nGetAlerts() result:")
			// begin-get_alerts

			getAlertsOptions := logsService.NewGetAlertsOptions()

			alertCollection, response, err := logsService.GetAlerts(getAlertsOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(alertCollection, "", "  ")
			fmt.Println(string(b))

			// end-get_alerts

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(alertCollection).ToNot(BeNil())
		})
		It(`GetRuleGroup request example`, func() {
			fmt.Println("\nGetRuleGroup() result:")
			// begin-get_rule_group

			getRuleGroupOptions := logsService.NewGetRuleGroupOptions(
				&ruleGroupIdLink,
			)

			ruleGroup, response, err := logsService.GetRuleGroup(getRuleGroupOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(ruleGroup, "", "  ")
			fmt.Println(string(b))

			// end-get_rule_group

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(ruleGroup).ToNot(BeNil())
		})
		It(`UpdateRuleGroup request example`, func() {
			fmt.Println("\nUpdateRuleGroup() result:")
			// begin-update_rule_group

			rulesV1ParseParametersModel := &logsv0.RulesV1ParseParameters{
				DestinationField: core.StringPtr("text"),
				Rule:             core.StringPtr("(?P<timestamp>[^,]+),(?P<hostname>[^,]+),(?P<username>[^,]+),(?P<ip>[^,]+),(?P<connectionId>[0-9]+),(?P<queryId>[0-9]+),(?P<operation>[^,]+),(?P<database>[^,]+),'?(?P<object>.*)'?,(?P<returnCode>[0-9]+)"),
			}

			rulesV1RuleParametersModel := &logsv0.RulesV1RuleParametersRuleParametersParseParameters{
				ParseParameters: rulesV1ParseParametersModel,
			}

			rulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRuleModel := &logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRule{
				Name:        core.StringPtr("mysql-parse"),
				Description: core.StringPtr("mysql-parse"),
				SourceField: core.StringPtr("text"),
				Parameters:  rulesV1RuleParametersModel,
				Enabled:     core.BoolPtr(true),
				Order:       core.Int64Ptr(int64(1)),
			}

			rulesV1CreateRuleGroupRequestCreateRuleSubgroupModel := &logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroup{
				Rules:   []logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRule{*rulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRuleModel},
				Enabled: core.BoolPtr(true),
				Order:   core.Int64Ptr(int64(1)),
			}

			rulesV1SubsystemNameConstraintModel := &logsv0.RulesV1SubsystemNameConstraint{
				Value: core.StringPtr("mysql"),
			}

			rulesV1RuleMatcherModel := &logsv0.RulesV1RuleMatcherConstraintSubsystemName{
				SubsystemName: rulesV1SubsystemNameConstraintModel,
			}

			updateRuleGroupOptions := logsService.NewUpdateRuleGroupOptions(
				&ruleGroupIdLink,
				"mysql-extractrule",
				[]logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroup{*rulesV1CreateRuleGroupRequestCreateRuleSubgroupModel},
			)
			updateRuleGroupOptions.SetDescription("mysql audit logs parser")
			updateRuleGroupOptions.SetEnabled(true)
			updateRuleGroupOptions.SetRuleMatchers([]logsv0.RulesV1RuleMatcherIntf{rulesV1RuleMatcherModel})
			updateRuleGroupOptions.SetOrder(int64(39))

			ruleGroup, response, err := logsService.UpdateRuleGroup(updateRuleGroupOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(ruleGroup, "", "  ")
			fmt.Println(string(b))

			// end-update_rule_group

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(ruleGroup).ToNot(BeNil())
		})
		It(`ListRuleGroups request example`, func() {
			fmt.Println("\nListRuleGroups() result:")
			// begin-list_rule_groups

			listRuleGroupsOptions := logsService.NewListRuleGroupsOptions()
			ruleGroupCollection, response, err := logsService.ListRuleGroups(listRuleGroupsOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(ruleGroupCollection, "", "  ")
			fmt.Println(string(b))

			// end-list_rule_groups

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(ruleGroupCollection).ToNot(BeNil())
		})
		It(`ListOutgoingWebhooks request example`, func() {
			fmt.Println("\nListOutgoingWebhooks() result:")
			// begin-list_outgoing_webhooks

			listOutgoingWebhooksOptions := logsService.NewListOutgoingWebhooksOptions()
			listOutgoingWebhooksOptions.SetType("ibm_event_notifications")

			outgoingWebhookCollection, response, err := logsService.ListOutgoingWebhooks(listOutgoingWebhooksOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(outgoingWebhookCollection, "", "  ")
			fmt.Println(string(b))

			// end-list_outgoing_webhooks

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(outgoingWebhookCollection).ToNot(BeNil())
		})
		It(`GetOutgoingWebhook request example`, func() {
			fmt.Println("\nGetOutgoingWebhook() result:")
			// begin-get_outgoing_webhook

			getOutgoingWebhookOptions := logsService.NewGetOutgoingWebhookOptions(
				&outgoingWebhookIdLink,
			)

			outgoingWebhook, response, err := logsService.GetOutgoingWebhook(getOutgoingWebhookOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(outgoingWebhook, "", "  ")
			fmt.Println(string(b))

			// end-get_outgoing_webhook

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(outgoingWebhook).ToNot(BeNil())
		})
		It(`UpdateOutgoingWebhook request example`, func() {
			fmt.Println("\nUpdateOutgoingWebhook() result:")
			// begin-update_outgoing_webhook

			outgoingWebhooksV1IbmEventNotificationsConfigModel := &logsv0.OutgoingWebhooksV1IbmEventNotificationsConfig{
				RegionID:                     core.StringPtr("us-south"),
				EventNotificationsInstanceID: CreateMockUUID("6964e1e9-74a2-4c6c-980b-d806ff75175d"),
			}

			outgoingWebhookPrototypeModel := &logsv0.OutgoingWebhookPrototypeOutgoingWebhooksV1OutgoingWebhookInputDataConfigIbmEventNotifications{
				Type:                  core.StringPtr("ibm_event_notifications"),
				Name:                  core.StringPtr("Event Notifications Integration"),
				IbmEventNotifications: outgoingWebhooksV1IbmEventNotificationsConfigModel,
			}

			updateOutgoingWebhookOptions := logsService.NewUpdateOutgoingWebhookOptions(
				&outgoingWebhookIdLink,
				outgoingWebhookPrototypeModel,
			)

			outgoingWebhook, response, err := logsService.UpdateOutgoingWebhook(updateOutgoingWebhookOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(outgoingWebhook, "", "  ")
			fmt.Println(string(b))

			// end-update_outgoing_webhook

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(outgoingWebhook).ToNot(BeNil())
		})
		It(`GetPolicy request example`, func() {
			fmt.Println("\nGetPolicy() result:")
			// begin-get_policy

			getPolicyOptions := logsService.NewGetPolicyOptions(
				&policyIdLink,
			)

			policy, response, err := logsService.GetPolicy(getPolicyOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(policy, "", "  ")
			fmt.Println(string(b))

			// end-get_policy

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(policy).ToNot(BeNil())
		})
		It(`UpdatePolicy request example`, func() {
			fmt.Println("\nUpdatePolicy() result:")
			// begin-update_policy

			quotaV1RuleModel := &logsv0.QuotaV1Rule{
				RuleTypeID: core.StringPtr("is"),
				Name:       core.StringPtr("policy-test"),
			}

			quotaV1LogRulesModel := &logsv0.QuotaV1LogRules{
				Severities: []string{"debug", "verbose", "info", "warning", "error"},
			}

			policyPrototypeModel := &logsv0.PolicyPrototypeQuotaV1CreatePolicyRequestSourceTypeRulesLogRules{
				Name:            core.StringPtr("Med_policy"),
				Description:     core.StringPtr("Medium policy"),
				Priority:        core.StringPtr("type_high"),
				ApplicationRule: quotaV1RuleModel,
				SubsystemRule:   quotaV1RuleModel,
				LogRules:        quotaV1LogRulesModel,
			}

			updatePolicyOptions := logsService.NewUpdatePolicyOptions(
				&policyIdLink,
				policyPrototypeModel,
			)

			policy, response, err := logsService.UpdatePolicy(updatePolicyOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(policy, "", "  ")
			fmt.Println(string(b))

			// end-update_policy

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(policy).ToNot(BeNil())
		})
		It(`GetCompanyPolicies request example`, func() {
			fmt.Println("\nGetCompanyPolicies() result:")
			// begin-get_company_policies

			getCompanyPoliciesOptions := logsService.NewGetCompanyPoliciesOptions()
			getCompanyPoliciesOptions.SetEnabledOnly(true)
			getCompanyPoliciesOptions.SetSourceType("logs")

			policyCollection, response, err := logsService.GetCompanyPolicies(getCompanyPoliciesOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(policyCollection, "", "  ")
			fmt.Println(string(b))

			// end-get_company_policies

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(policyCollection).ToNot(BeNil())
		})
		It(`GetDashboard request example`, func() {
			fmt.Println("\nGetDashboard() result:")
			// begin-get_dashboard

			getDashboardOptions := logsService.NewGetDashboardOptions(
				dashboardIdLink,
			)

			dashboard, response, err := logsService.GetDashboard(getDashboardOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(dashboard, "", "  ")
			fmt.Println(string(b))

			// end-get_dashboard

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(dashboard).ToNot(BeNil())
		})
		It(`ReplaceDashboard request example`, func() {
			fmt.Println("\nReplaceDashboard() result:")
			// begin-replace_dashboard

			apisDashboardsV1UUIDModel := &logsv0.ApisDashboardsV1UUID{
				Value: CreateMockUUID("10c27980-3532-21b0-8069-0c9110f03c90"),
			}

			apisDashboardsV1AstRowAppearanceModel := &logsv0.ApisDashboardsV1AstRowAppearance{
				Height: core.Int64Ptr(int64(19)),
			}

			apisDashboardsV1AstWidgetsCommonLegendModel := &logsv0.ApisDashboardsV1AstWidgetsCommonLegend{
				IsVisible:    core.BoolPtr(true),
				GroupByQuery: core.BoolPtr(true),
			}

			apisDashboardsV1AstWidgetsLineChartTooltipModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartTooltip{
				ShowLabels: core.BoolPtr(false),
				Type:       core.StringPtr("all"),
			}

			apisDashboardsV1AstWidgetsCommonPromQlQueryModel := &logsv0.ApisDashboardsV1AstWidgetsCommonPromQlQuery{
				Value: core.StringPtr("sum(rate(cx_data_usage_bytes_total[20m]))by(pillar,tier)"),
			}

			apisDashboardsV1AstWidgetsLineChartMetricsQueryModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartMetricsQuery{
				PromqlQuery: apisDashboardsV1AstWidgetsCommonPromQlQueryModel,
			}

			apisDashboardsV1AstWidgetsLineChartQueryModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartQueryValueMetrics{
				Metrics: apisDashboardsV1AstWidgetsLineChartMetricsQueryModel,
			}

			apisDashboardsV1AstWidgetsLineChartResolutionModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartResolution{
				BucketsPresented: core.Int64Ptr(int64(96)),
			}

			apisDashboardsV1AstWidgetsLineChartQueryDefinitionModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartQueryDefinition{
				ID:               CreateMockUUID("e4560525-521c-49e7-a7de-a2925626c304"),
				Query:            apisDashboardsV1AstWidgetsLineChartQueryModel,
				SeriesCountLimit: core.StringPtr("20"),
				ScaleType:        core.StringPtr("linear"),
				Name:             core.StringPtr("Query1"),
				IsVisible:        core.BoolPtr(true),
				ColorScheme:      core.StringPtr("classic"),
				Resolution:       apisDashboardsV1AstWidgetsLineChartResolutionModel,
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
				ID:         apisDashboardsV1UUIDModel,
				Title:      core.StringPtr("Size"),
				Definition: apisDashboardsV1AstWidgetDefinitionModel,
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

			apisDashboardsV1AstFilterEqualsSelectionListSelectionModel := &logsv0.ApisDashboardsV1AstFilterEqualsSelectionListSelection{}

			apisDashboardsV1AstFilterEqualsSelectionModel := &logsv0.ApisDashboardsV1AstFilterEqualsSelectionValueList{
				List: apisDashboardsV1AstFilterEqualsSelectionListSelectionModel,
			}

			apisDashboardsV1AstFilterEqualsModel := &logsv0.ApisDashboardsV1AstFilterEquals{
				Selection: apisDashboardsV1AstFilterEqualsSelectionModel,
			}

			apisDashboardsV1AstFilterOperatorModel := &logsv0.ApisDashboardsV1AstFilterOperatorValueEquals{
				Equals: apisDashboardsV1AstFilterEqualsModel,
			}

			apisDashboardsV1CommonObservationFieldModel := &logsv0.ApisDashboardsV1CommonObservationField{
				Keypath: []string{"applicationname"},
				Scope:   core.StringPtr("label"),
			}

			apisDashboardsV1AstFilterLogsFilterModel := &logsv0.ApisDashboardsV1AstFilterLogsFilter{
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

			dashboardModel := &logsv0.DashboardApisDashboardsV1AstDashboardTimeFrameRelativeTimeFrame{
				Name:              core.StringPtr("DataUsageToMetrics Dashboard"),
				Layout:            apisDashboardsV1AstLayoutModel,
				Filters:           []logsv0.ApisDashboardsV1AstFilter{*apisDashboardsV1AstFilterModel},
				RelativeTimeFrame: core.StringPtr("86400s"),
			}

			replaceDashboardOptions := logsService.NewReplaceDashboardOptions(
				dashboardIdLink,
				dashboardModel,
			)

			dashboard, response, err := logsService.ReplaceDashboard(replaceDashboardOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(dashboard, "", "  ")
			fmt.Println(string(b))

			// end-replace_dashboard

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(dashboard).ToNot(BeNil())
		})
		It(`PinDashboard request example`, func() {
			fmt.Println("\nPinDashboard() result:")
			// begin-pin_dashboard

			pinDashboardOptions := logsService.NewPinDashboardOptions(
				dashboardIdLink,
			)

			pinDashboardResponse, response, err := logsService.PinDashboard(pinDashboardOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(pinDashboardResponse, "", "  ")
			fmt.Println(string(b))

			// end-pin_dashboard

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(pinDashboardResponse).ToNot(BeNil())
		})
		It(`ReplaceDefaultDashboard request example`, func() {
			fmt.Println("\nReplaceDefaultDashboard() result:")
			// begin-replace_default_dashboard

			replaceDefaultDashboardOptions := logsService.NewReplaceDefaultDashboardOptions(
				dashboardIdLink,
			)

			replaceDefaultDashboardResponse, response, err := logsService.ReplaceDefaultDashboard(replaceDefaultDashboardOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(replaceDefaultDashboardResponse, "", "  ")
			fmt.Println(string(b))

			// end-replace_default_dashboard

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(replaceDefaultDashboardResponse).ToNot(BeNil())
		})
		It(`AssignDashboardFolder request example`, func() {
			fmt.Println("\nAssignDashboardFolder() result:")
			// begin-assign_dashboard_folder

			assignDashboardFolderOptions := logsService.NewAssignDashboardFolderOptions(
				dashboardIdLink,
				folderIdLink.String(),
			)

			assignDashboardFolderResponse, response, err := logsService.AssignDashboardFolder(assignDashboardFolderOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(assignDashboardFolderResponse, "", "  ")
			fmt.Println(string(b))

			// end-assign_dashboard_folder

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(assignDashboardFolderResponse).ToNot(BeNil())
		})
		It(`ListDashboardFolders request example`, func() {
			fmt.Println("\nListDashboardFolders() result:")
			// begin-list_dashboard_folders

			listDashboardFoldersOptions := logsService.NewListDashboardFoldersOptions()

			dashboardFolderCollection, response, err := logsService.ListDashboardFolders(listDashboardFoldersOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(dashboardFolderCollection, "", "  ")
			fmt.Println(string(b))

			// end-list_dashboard_folders

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(dashboardFolderCollection).ToNot(BeNil())
		})
		It(`ReplaceDashboardFolder request example`, func() {
			fmt.Println("\nReplaceDashboardFolder() result:")
			// begin-replace_dashboard_folder

			replaceDashboardFolderOptions := logsService.NewReplaceDashboardFolderOptions(
				&folderIdLink,
				"My Folder",
			)

			dashboardFolder, response, err := logsService.ReplaceDashboardFolder(replaceDashboardFolderOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(dashboardFolder, "", "  ")
			fmt.Println(string(b))

			// end-replace_dashboard_folder

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(dashboardFolder).ToNot(BeNil())
		})
		It(`ListE2m request example`, func() {
			fmt.Println("\nListE2m() result:")
			// begin-list_e2m

			listE2mOptions := logsService.NewListE2mOptions()

			event2MetricCollection, response, err := logsService.ListE2m(listE2mOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(event2MetricCollection, "", "  ")
			fmt.Println(string(b))

			// end-list_e2m

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(event2MetricCollection).ToNot(BeNil())
		})
		It(`GetE2m request example`, func() {
			fmt.Println("\nGetE2m() result:")
			// begin-get_e2m

			getE2mOptions := logsService.NewGetE2mOptions(
				events2MetricsIdLink.String(),
			)

			event2Metric, response, err := logsService.GetE2m(getE2mOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(event2Metric, "", "  ")
			fmt.Println(string(b))

			// end-get_e2m

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(event2Metric).ToNot(BeNil())
		})
		It(`ReplaceE2m request example`, func() {
			fmt.Println("\nReplaceE2m() result:")
			// begin-replace_e2m

			apisLogs2metricsV2LogsQueryModel := &logsv0.ApisLogs2metricsV2LogsQuery{
				Lucene: core.StringPtr("logs"),
			}

			event2MetricPrototypeModel := &logsv0.Event2MetricPrototypeApisEvents2metricsV2E2mCreateParamsQueryLogsQuery{
				Name:              core.StringPtr("test em2"),
				Description:       core.StringPtr("Test e2m updated"),
				PermutationsLimit: core.Int64Ptr(int64(1)),
				Type:              core.StringPtr("logs2metrics"),
				LogsQuery:         apisLogs2metricsV2LogsQueryModel,
			}

			replaceE2mOptions := logsService.NewReplaceE2mOptions(
				events2MetricsIdLink.String(),
				event2MetricPrototypeModel,
			)

			event2Metric, response, err := logsService.ReplaceE2m(replaceE2mOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(event2Metric, "", "  ")
			fmt.Println(string(b))

			// end-replace_e2m

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(event2Metric).ToNot(BeNil())
		})
		It(`ListViews request example`, func() {
			fmt.Println("\nListViews() result:")
			// begin-list_views

			listViewsOptions := logsService.NewListViewsOptions()

			viewCollection, response, err := logsService.ListViews(listViewsOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(viewCollection, "", "  ")
			fmt.Println(string(b))

			// end-list_views

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(viewCollection).ToNot(BeNil())
		})
		It(`GetView request example`, func() {
			fmt.Println("\nGetView() result:")
			// begin-get_view

			getViewOptions := logsService.NewGetViewOptions(
				viewIdLink,
			)

			view, response, err := logsService.GetView(getViewOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(view, "", "  ")
			fmt.Println(string(b))

			// end-get_view

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(view).ToNot(BeNil())
		})
		It(`ReplaceView request example`, func() {
			fmt.Println("\nReplaceView() result:")
			// begin-replace_view

			apisViewsV1SearchQueryModel := &logsv0.ApisViewsV1SearchQuery{
				Query: core.StringPtr("logs new"),
			}

			apisViewsV1CustomTimeSelectionModel := &logsv0.ApisViewsV1CustomTimeSelection{
				FromTime: CreateMockDateTime("2024-01-25T11:31:43.152Z"),
				ToTime:   CreateMockDateTime("2024-01-25T11:37:13.238Z"),
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

			replaceViewOptions := logsService.NewReplaceViewOptions(
				viewIdLink,
				"Logs view",
				apisViewsV1SearchQueryModel,
				apisViewsV1TimeSelectionModel,
			)
			replaceViewOptions.SetFilters(apisViewsV1SelectedFiltersModel)

			view, response, err := logsService.ReplaceView(replaceViewOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(view, "", "  ")
			fmt.Println(string(b))

			// end-replace_view

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(view).ToNot(BeNil())
		})
		It(`ListViewFolders request example`, func() {
			fmt.Println("\nListViewFolders() result:")
			// begin-list_view_folders

			listViewFoldersOptions := logsService.NewListViewFoldersOptions()

			viewFolderCollection, response, err := logsService.ListViewFolders(listViewFoldersOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(viewFolderCollection, "", "  ")
			fmt.Println(string(b))

			// end-list_view_folders

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(viewFolderCollection).ToNot(BeNil())
		})
		It(`GetViewFolder request example`, func() {
			fmt.Println("\nGetViewFolder() result:")
			// begin-get_view_folder

			getViewFolderOptions := logsService.NewGetViewFolderOptions(
				&viewFolderIdLink,
			)

			viewFolder, response, err := logsService.GetViewFolder(getViewFolderOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(viewFolder, "", "  ")
			fmt.Println(string(b))

			// end-get_view_folder

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(viewFolder).ToNot(BeNil())
		})
		It(`ReplaceViewFolder request example`, func() {
			fmt.Println("\nReplaceViewFolder() result:")
			// begin-replace_view_folder

			replaceViewFolderOptions := logsService.NewReplaceViewFolderOptions(
				&viewFolderIdLink,
				"My Folder",
			)

			viewFolder, response, err := logsService.ReplaceViewFolder(replaceViewFolderOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(viewFolder, "", "  ")
			fmt.Println(string(b))

			// end-replace_view_folder

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(viewFolder).ToNot(BeNil())
		})
		It(`DeleteAlert request example`, func() {
			// begin-delete_alert

			deleteAlertOptions := logsService.NewDeleteAlertOptions(
				&alertIdLink,
			)

			response, err := logsService.DeleteAlert(deleteAlertOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeleteAlert(): %d\n", response.StatusCode)
			}

			// end-delete_alert

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`DeleteRuleGroup request example`, func() {
			// begin-delete_rule_group

			deleteRuleGroupOptions := logsService.NewDeleteRuleGroupOptions(
				&ruleGroupIdLink,
			)

			response, err := logsService.DeleteRuleGroup(deleteRuleGroupOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeleteRuleGroup(): %d\n", response.StatusCode)
			}

			// end-delete_rule_group

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`DeleteOutgoingWebhook request example`, func() {
			// begin-delete_outgoing_webhook

			deleteOutgoingWebhookOptions := logsService.NewDeleteOutgoingWebhookOptions(
				&outgoingWebhookIdLink,
			)

			response, err := logsService.DeleteOutgoingWebhook(deleteOutgoingWebhookOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeleteOutgoingWebhook(): %d\n", response.StatusCode)
			}

			// end-delete_outgoing_webhook

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`DeletePolicy request example`, func() {
			// begin-delete_policy

			deletePolicyOptions := logsService.NewDeletePolicyOptions(
				&policyIdLink,
			)

			response, err := logsService.DeletePolicy(deletePolicyOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeletePolicy(): %d\n", response.StatusCode)
			}

			// end-delete_policy

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`UnpinDashboard request example`, func() {
			// begin-unpin_dashboard

			unpinDashboardOptions := logsService.NewUnpinDashboardOptions(
				dashboardIdLink,
			)

			response, err := logsService.UnpinDashboard(unpinDashboardOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from UnpinDashboard(): %d\n", response.StatusCode)
			}

			// end-unpin_dashboard

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`DeleteDashboard request example`, func() {
			// begin-delete_dashboard

			deleteDashboardOptions := logsService.NewDeleteDashboardOptions(
				dashboardIdLink,
			)

			response, err := logsService.DeleteDashboard(deleteDashboardOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeleteDashboard(): %d\n", response.StatusCode)
			}

			// end-delete_dashboard

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`DeleteDashboardFolder request example`, func() {
			// begin-delete_dashboard_folder

			deleteDashboardFolderOptions := logsService.NewDeleteDashboardFolderOptions(
				&folderIdLink,
			)

			response, err := logsService.DeleteDashboardFolder(deleteDashboardFolderOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeleteDashboardFolder(): %d\n", response.StatusCode)
			}

			// end-delete_dashboard_folder

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`DeleteE2m request example`, func() {
			// begin-delete_e2m

			deleteE2mOptions := logsService.NewDeleteE2mOptions(
				events2MetricsIdLink.String(),
			)

			response, err := logsService.DeleteE2m(deleteE2mOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeleteE2m(): %d\n", response.StatusCode)
			}

			// end-delete_e2m

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`DeleteView request example`, func() {
			// begin-delete_view

			deleteViewOptions := logsService.NewDeleteViewOptions(
				viewIdLink,
			)

			response, err := logsService.DeleteView(deleteViewOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeleteView(): %d\n", response.StatusCode)
			}

			// end-delete_view

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`DeleteViewFolder request example`, func() {
			// begin-delete_view_folder

			deleteViewFolderOptions := logsService.NewDeleteViewFolderOptions(
				&viewFolderIdLink,
			)

			response, err := logsService.DeleteViewFolder(deleteViewFolderOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeleteViewFolder(): %d\n", response.StatusCode)
			}

			// end-delete_view_folder

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})
})
