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
	"fmt"
	"log"
	"os"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/go-openapi/strfmt"
	"github.com/IBM/logs-go-sdk/logsv0"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

/**
 * This file contains an integration test for the logsv0 package.
 *
 * Notes:
 *
 * The integration test will automatically skip tests if the required config file is not available.
 */

var _ = Describe(`LogsV0 Integration Tests`, func() {
	const externalConfigFile = "../logs.env"

	var (
		err         error
		logsService *logsv0.LogsV0
		serviceURL  string
		config      map[string]string

		// Variables to hold link values
		alertIdLink           strfmt.UUID
		dataAccessRuleIdLink  strfmt.UUID
		dashboardIdLink       string
		encrichmentsIdLink    int64
		events2MetricsIdLink  strfmt.UUID
		folderIdLink          strfmt.UUID
		outgoingWebhookIdLink strfmt.UUID
		policyIdLink          strfmt.UUID
		ruleGroupIdLink       strfmt.UUID
		viewFolderIdLink      strfmt.UUID
		viewIdLink            int64
	)

	var shouldSkipTest = func() {
		Skip("External configuration is not available, skipping tests...")
	}

	Describe(`External configuration`, func() {
		It("Successfully load the configuration", func() {
			_, err = os.Stat(externalConfigFile)
			if err != nil {
				Skip("External configuration file not found, skipping tests: " + err.Error())
			}

			os.Setenv("IBM_CREDENTIALS_FILE", externalConfigFile)
			config, err = core.GetServiceProperties(logsv0.DefaultServiceName)
			if err != nil {
				Skip("Error loading service properties, skipping tests: " + err.Error())
			}
			serviceURL = config["URL"]
			if serviceURL == "" {
				Skip("Unable to load service URL configuration property, skipping tests")
			}

			fmt.Fprintf(GinkgoWriter, "Service URL: %v\n", serviceURL)
			shouldSkipTest = func() {}
		})
	})

	Describe(`Client initialization`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It("Successfully construct the service client instance", func() {
			logsServiceOptions := &logsv0.LogsV0Options{}

			logsService, err = logsv0.NewLogsV0UsingExternalConfig(logsServiceOptions)
			Expect(err).To(BeNil())
			Expect(logsService).ToNot(BeNil())
			Expect(logsService.Service.Options.URL).To(Equal(serviceURL))

			core.SetLogger(core.NewLogger(core.LevelDebug, log.New(GinkgoWriter, "", log.LstdFlags), log.New(GinkgoWriter, "", log.LstdFlags)))
			logsService.EnableRetries(4, 30*time.Second)
		})
	})

	Describe(`CreateAlert - Create an alert`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateAlert(createAlertOptions *CreateAlertOptions)`, func() {
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

			createAlertOptions := &logsv0.CreateAlertOptions{
				Name:                       core.StringPtr("Test alert"),
				IsActive:                   core.BoolPtr(true),
				Severity:                   core.StringPtr("info_or_unspecified"),
				Condition:                  alertsV2AlertConditionModel,
				NotificationGroups:         []logsv0.AlertsV2AlertNotificationGroups{*alertsV2AlertNotificationGroupsModel},
				Filters:                    alertsV1AlertFiltersModel,
				Description:                core.StringPtr("Alert if the number of logs reaches a threshold"),
				ActiveWhen:                 alertsV1AlertActiveWhenModel,
				NotificationPayloadFilters: []string{"testString"},
				MetaLabels:                 []logsv0.AlertsV1MetaLabel{*alertsV1MetaLabelModel},
				MetaLabelsStrings:          []string{},
				IncidentSettings:           alertsV2AlertIncidentSettingsModel,
			}

			alert, response, err := logsService.CreateAlert(createAlertOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(alert).ToNot(BeNil())

			alertIdLink = *alert.ID
			fmt.Fprintf(GinkgoWriter, "Saved alertIdLink value: %v\n", alertIdLink)
		})
	})

	Describe(`CreateRuleGroup - Creates rule group`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateRuleGroup(createRuleGroupOptions *CreateRuleGroupOptions)`, func() {
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

			createRuleGroupOptions := &logsv0.CreateRuleGroupOptions{
				Name:          core.StringPtr("mysql-extractrule"),
				RuleSubgroups: []logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroup{*rulesV1CreateRuleGroupRequestCreateRuleSubgroupModel},
				Description:   core.StringPtr("mysql audit logs  parser"),
				Enabled:       core.BoolPtr(true),
				RuleMatchers:  []logsv0.RulesV1RuleMatcherIntf{rulesV1RuleMatcherModel},
				Order:         core.Int64Ptr(int64(39)),
			}

			ruleGroup, response, err := logsService.CreateRuleGroup(createRuleGroupOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(ruleGroup).ToNot(BeNil())

			ruleGroupIdLink = *ruleGroup.ID
			fmt.Fprintf(GinkgoWriter, "Saved ruleGroupIdLink value: %v\n", ruleGroupIdLink)
		})
	})

	Describe(`CreateOutgoingWebhook - Create an Outbound Integration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateOutgoingWebhook(createOutgoingWebhookOptions *CreateOutgoingWebhookOptions)`, func() {
			outgoingWebhooksV1IbmEventNotificationsConfigModel := &logsv0.OutgoingWebhooksV1IbmEventNotificationsConfig{
				RegionID:                     core.StringPtr(config["IBM_EVENT_NOTIFICATIONS_INSTANCE_REGION"]),
				EventNotificationsInstanceID: CreateMockUUID(config["IBM_EVENT_NOTIFICATIONS_INSTANCE_ID"]),
			}

			outgoingWebhookPrototypeModel := &logsv0.OutgoingWebhookPrototypeOutgoingWebhooksV1OutgoingWebhookInputDataConfigIbmEventNotifications{
				Type:                  core.StringPtr("ibm_event_notifications"),
				Name:                  core.StringPtr("Event Notifications Integration"),
				IbmEventNotifications: outgoingWebhooksV1IbmEventNotificationsConfigModel,
			}

			createOutgoingWebhookOptions := &logsv0.CreateOutgoingWebhookOptions{
				OutgoingWebhookPrototype: outgoingWebhookPrototypeModel,
			}

			outgoingWebhook, response, err := logsService.CreateOutgoingWebhook(createOutgoingWebhookOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(outgoingWebhook).ToNot(BeNil())

			outgoingWebhookIdLink = *outgoingWebhook.(*logsv0.OutgoingWebhook).ID
			fmt.Fprintf(GinkgoWriter, "Saved outgoingWebhookIdLink value: %v\n", outgoingWebhookIdLink)
		})
	})

	Describe(`CreatePolicy - Creates a new policy`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreatePolicy(createPolicyOptions *CreatePolicyOptions)`, func() {
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

			createPolicyOptions := &logsv0.CreatePolicyOptions{
				PolicyPrototype: policyPrototypeModel,
			}

			policy, response, err := logsService.CreatePolicy(createPolicyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(policy).ToNot(BeNil())

			policyIdLink = *policy.(*logsv0.Policy).ID
			fmt.Fprintf(GinkgoWriter, "Saved policyIdLink value: %v\n", policyIdLink)
		})
	})

	Describe(`CreateDashboard - Creates a new dashboard`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateDashboard(createDashboardOptions *CreateDashboardOptions)`, func() {
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

			createDashboardOptions := &logsv0.CreateDashboardOptions{
				Dashboard: dashboardModel,
			}

			dashboard, response, err := logsService.CreateDashboard(createDashboardOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(dashboard).ToNot(BeNil())

			dashboardIdLink = *dashboard.(*logsv0.Dashboard).ID
			fmt.Fprintf(GinkgoWriter, "Saved dashboardIdLink value: %v\n", dashboardIdLink)
		})
	})

	Describe(`CreateDashboardFolder - Create a dashboard folder`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateDashboardFolder(createDashboardFolderOptions *CreateDashboardFolderOptions)`, func() {
			createDashboardFolderOptions := &logsv0.CreateDashboardFolderOptions{
				Name: core.StringPtr("My Folder"),
			}

			dashboardFolder, response, err := logsService.CreateDashboardFolder(createDashboardFolderOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(dashboardFolder).ToNot(BeNil())

			folderIdLink = *dashboardFolder.ID
			fmt.Fprintf(GinkgoWriter, "Saved folderIdLink value: %v\n", folderIdLink)
		})
	})

	Describe(`CreateE2m - Creates event to metrics definitions`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateE2m(createE2mOptions *CreateE2mOptions)`, func() {
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

			createE2mOptions := &logsv0.CreateE2mOptions{
				Event2MetricPrototype: event2MetricPrototypeModel,
			}

			event2Metric, response, err := logsService.CreateE2m(createE2mOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(event2Metric).ToNot(BeNil())

			events2MetricsIdLink = *event2Metric.(*logsv0.Event2Metric).ID
			fmt.Fprintf(GinkgoWriter, "Saved events2MetricsIdLink value: %v\n", events2MetricsIdLink)
		})
	})

	Describe(`CreateView - Creates a new view`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateView(createViewOptions *CreateViewOptions)`, func() {
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

			createViewOptions := &logsv0.CreateViewOptions{
				Name:          core.StringPtr("Logs view"),
				SearchQuery:   apisViewsV1SearchQueryModel,
				TimeSelection: apisViewsV1TimeSelectionModel,
				Filters:       apisViewsV1SelectedFiltersModel,
			}

			view, response, err := logsService.CreateView(createViewOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(view).ToNot(BeNil())

			viewIdLink = *view.ID
			fmt.Fprintf(GinkgoWriter, "Saved viewIdLink value: %v\n", viewIdLink)
		})
	})

	Describe(`CreateViewFolder - Create view folder`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateViewFolder(createViewFolderOptions *CreateViewFolderOptions)`, func() {
			createViewFolderOptions := &logsv0.CreateViewFolderOptions{
				Name: core.StringPtr("My Folder"),
			}

			viewFolder, response, err := logsService.CreateViewFolder(createViewFolderOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(viewFolder).ToNot(BeNil())

			viewFolderIdLink = *viewFolder.ID
			fmt.Fprintf(GinkgoWriter, "Saved viewFolderIdLink value: %v\n", viewFolderIdLink)
		})
	})

	Describe(`CreateEnrichment - Create an enrichment`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateEnrichment(createEnrichmentOptions *CreateEnrichmentOptions)`, func() {
			enrichmentV1GeoIpTypeEmptyModel := &logsv0.EnrichmentV1GeoIpTypeEmpty{}

			enrichmentV1EnrichmentTypeModel := &logsv0.EnrichmentV1EnrichmentTypeTypeGeoIp{
				GeoIp: enrichmentV1GeoIpTypeEmptyModel,
			}

			createEnrichmentOptions := &logsv0.CreateEnrichmentOptions{
				FieldName:      core.StringPtr("ip"),
				EnrichmentType: enrichmentV1EnrichmentTypeModel,
			}

			enrichment, response, err := logsService.CreateEnrichment(createEnrichmentOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(enrichment).ToNot(BeNil())

			encrichmentsIdLink = *enrichment.ID
			fmt.Fprintf(GinkgoWriter, "Saved encrichmentsIdLink value: %v\n", encrichmentsIdLink)
		})
	})

	Describe(`CreateDataAccessRule - Create a Data Access Rule`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateDataAccessRule(createDataAccessRuleOptions *CreateDataAccessRuleOptions)`, func() {
			dataAccessRuleFilterModel := &logsv0.DataAccessRuleFilter{
				EntityType: core.StringPtr("logs"),
				Expression: core.StringPtr("<v1> foo == 'bar'"),
			}

			createDataAccessRuleOptions := &logsv0.CreateDataAccessRuleOptions{
				DisplayName:       core.StringPtr("Test Data Access Rule"),
				Filters:           []logsv0.DataAccessRuleFilter{*dataAccessRuleFilterModel},
				DefaultExpression: core.StringPtr("<v1>true"),
				Description:       core.StringPtr("Data Access Rule intended for testing"),
			}

			dataAccessRule, response, err := logsService.CreateDataAccessRule(createDataAccessRuleOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(dataAccessRule).ToNot(BeNil())

			dataAccessRuleIdLink = *dataAccessRule.ID
			fmt.Fprintf(GinkgoWriter, "Saved dataAccessRuleIdLink value: %v\n", dataAccessRuleIdLink)
		})
	})

	Describe(`GetAlert - Get an alert by ID`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetAlert(getAlertOptions *GetAlertOptions)`, func() {
			getAlertOptions := &logsv0.GetAlertOptions{
				ID: &alertIdLink,
			}

			alert, response, err := logsService.GetAlert(getAlertOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(alert).ToNot(BeNil())
		})
	})

	Describe(`UpdateAlert - Update an alert`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateAlert(updateAlertOptions *UpdateAlertOptions)`, func() {
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

			updateAlertOptions := &logsv0.UpdateAlertOptions{
				ID:                         &alertIdLink,
				Name:                       core.StringPtr("Test alert"),
				IsActive:                   core.BoolPtr(true),
				Severity:                   core.StringPtr("info_or_unspecified"),
				Condition:                  alertsV2AlertConditionModel,
				NotificationGroups:         []logsv0.AlertsV2AlertNotificationGroups{*alertsV2AlertNotificationGroupsModel},
				Filters:                    alertsV1AlertFiltersModel,
				Description:                core.StringPtr("Alert if the number of logs reaches a threshold"),
				ActiveWhen:                 alertsV1AlertActiveWhenModel,
				NotificationPayloadFilters: []string{"testString"},
				MetaLabels:                 []logsv0.AlertsV1MetaLabel{*alertsV1MetaLabelModel},
				MetaLabelsStrings:          []string{},
				IncidentSettings:           alertsV2AlertIncidentSettingsModel,
			}

			alert, response, err := logsService.UpdateAlert(updateAlertOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(alert).ToNot(BeNil())
		})
	})

	Describe(`GetAlerts - List alerts`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetAlerts(getAlertsOptions *GetAlertsOptions)`, func() {
			getAlertsOptions := &logsv0.GetAlertsOptions{}

			alertCollection, response, err := logsService.GetAlerts(getAlertsOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(alertCollection).ToNot(BeNil())
		})
	})

	Describe(`GetRuleGroup - Gets rule group by groupid`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetRuleGroup(getRuleGroupOptions *GetRuleGroupOptions)`, func() {
			getRuleGroupOptions := &logsv0.GetRuleGroupOptions{
				GroupID: &ruleGroupIdLink,
			}

			ruleGroup, response, err := logsService.GetRuleGroup(getRuleGroupOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(ruleGroup).ToNot(BeNil())
		})
	})

	Describe(`UpdateRuleGroup - Updates rule group by groupid`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateRuleGroup(updateRuleGroupOptions *UpdateRuleGroupOptions)`, func() {
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

			updateRuleGroupOptions := &logsv0.UpdateRuleGroupOptions{
				GroupID:       &ruleGroupIdLink,
				Name:          core.StringPtr("mysql-extractrule"),
				RuleSubgroups: []logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroup{*rulesV1CreateRuleGroupRequestCreateRuleSubgroupModel},
				Description:   core.StringPtr("mysql audit logs parser"),
				Enabled:       core.BoolPtr(true),
				RuleMatchers:  []logsv0.RulesV1RuleMatcherIntf{rulesV1RuleMatcherModel},
				Order:         core.Int64Ptr(int64(39)),
			}

			ruleGroup, response, err := logsService.UpdateRuleGroup(updateRuleGroupOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(ruleGroup).ToNot(BeNil())
		})
	})

	Describe(`ListRuleGroups - Gets all rule groups`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListRuleGroups(listRuleGroupsOptions *ListRuleGroupsOptions)`, func() {
			listRuleGroupsOptions := &logsv0.ListRuleGroupsOptions{}

			ruleGroupCollection, response, err := logsService.ListRuleGroups(listRuleGroupsOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(ruleGroupCollection).ToNot(BeNil())
		})
	})

	Describe(`ListOutgoingWebhooks - List Outbound Integrations`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListOutgoingWebhooks(listOutgoingWebhooksOptions *ListOutgoingWebhooksOptions)`, func() {
			listOutgoingWebhooksOptions := &logsv0.ListOutgoingWebhooksOptions{
				Type: core.StringPtr("ibm_event_notifications"),
			}

			outgoingWebhookCollection, response, err := logsService.ListOutgoingWebhooks(listOutgoingWebhooksOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(outgoingWebhookCollection).ToNot(BeNil())
		})
	})

	Describe(`GetOutgoingWebhook - Gets an Outbound Integration by ID`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetOutgoingWebhook(getOutgoingWebhookOptions *GetOutgoingWebhookOptions)`, func() {
			getOutgoingWebhookOptions := &logsv0.GetOutgoingWebhookOptions{
				ID: &outgoingWebhookIdLink,
			}

			outgoingWebhook, response, err := logsService.GetOutgoingWebhook(getOutgoingWebhookOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(outgoingWebhook).ToNot(BeNil())
		})
	})

	Describe(`UpdateOutgoingWebhook - Update an Outbound Integration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateOutgoingWebhook(updateOutgoingWebhookOptions *UpdateOutgoingWebhookOptions)`, func() {
			outgoingWebhooksV1IbmEventNotificationsConfigModel := &logsv0.OutgoingWebhooksV1IbmEventNotificationsConfig{
				RegionID:                     core.StringPtr(config["IBM_EVENT_NOTIFICATIONS_INSTANCE_REGION"]),
				EventNotificationsInstanceID: CreateMockUUID(config["IBM_EVENT_NOTIFICATIONS_INSTANCE_ID"]),
			}

			outgoingWebhookPrototypeModel := &logsv0.OutgoingWebhookPrototypeOutgoingWebhooksV1OutgoingWebhookInputDataConfigIbmEventNotifications{
				Type:                  core.StringPtr("ibm_event_notifications"),
				Name:                  core.StringPtr("Event Notifications Integration"),
				IbmEventNotifications: outgoingWebhooksV1IbmEventNotificationsConfigModel,
			}

			updateOutgoingWebhookOptions := &logsv0.UpdateOutgoingWebhookOptions{
				ID:                       &outgoingWebhookIdLink,
				OutgoingWebhookPrototype: outgoingWebhookPrototypeModel,
			}

			outgoingWebhook, response, err := logsService.UpdateOutgoingWebhook(updateOutgoingWebhookOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(outgoingWebhook).ToNot(BeNil())
		})
	})

	Describe(`GetPolicy - Gets policy by id`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetPolicy(getPolicyOptions *GetPolicyOptions)`, func() {
			getPolicyOptions := &logsv0.GetPolicyOptions{
				ID: &policyIdLink,
			}

			policy, response, err := logsService.GetPolicy(getPolicyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(policy).ToNot(BeNil())
		})
	})

	Describe(`UpdatePolicy - Updates an existing policy`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdatePolicy(updatePolicyOptions *UpdatePolicyOptions)`, func() {
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

			updatePolicyOptions := &logsv0.UpdatePolicyOptions{
				ID:              &policyIdLink,
				PolicyPrototype: policyPrototypeModel,
			}

			policy, response, err := logsService.UpdatePolicy(updatePolicyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(policy).ToNot(BeNil())
		})
	})

	Describe(`GetCompanyPolicies - Gets policies`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetCompanyPolicies(getCompanyPoliciesOptions *GetCompanyPoliciesOptions)`, func() {
			getCompanyPoliciesOptions := &logsv0.GetCompanyPoliciesOptions{
				EnabledOnly: core.BoolPtr(true),
				SourceType:  core.StringPtr("logs"),
			}

			policyCollection, response, err := logsService.GetCompanyPolicies(getCompanyPoliciesOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(policyCollection).ToNot(BeNil())
		})
	})

	Describe(`GetDashboard - Gets an existing dashboard`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetDashboard(getDashboardOptions *GetDashboardOptions)`, func() {
			getDashboardOptions := &logsv0.GetDashboardOptions{
				DashboardID: &dashboardIdLink,
			}

			dashboard, response, err := logsService.GetDashboard(getDashboardOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(dashboard).ToNot(BeNil())
		})
	})

	Describe(`ReplaceDashboard - Replaces an existing dashboard`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ReplaceDashboard(replaceDashboardOptions *ReplaceDashboardOptions)`, func() {
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

			replaceDashboardOptions := &logsv0.ReplaceDashboardOptions{
				DashboardID: &dashboardIdLink,
				Dashboard:   dashboardModel,
			}

			dashboard, response, err := logsService.ReplaceDashboard(replaceDashboardOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(dashboard).ToNot(BeNil())
		})
	})

	Describe(`PinDashboard - Add dashboard to the favorite folder`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`PinDashboard(pinDashboardOptions *PinDashboardOptions)`, func() {
			pinDashboardOptions := &logsv0.PinDashboardOptions{
				DashboardID: &dashboardIdLink,
			}

			pinDashboardResponse, response, err := logsService.PinDashboard(pinDashboardOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(pinDashboardResponse).ToNot(BeNil())
		})
	})

	Describe(`ReplaceDefaultDashboard - Set dashboard as the default dashboard for the user`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ReplaceDefaultDashboard(replaceDefaultDashboardOptions *ReplaceDefaultDashboardOptions)`, func() {
			replaceDefaultDashboardOptions := &logsv0.ReplaceDefaultDashboardOptions{
				DashboardID: &dashboardIdLink,
			}

			replaceDefaultDashboardResponse, response, err := logsService.ReplaceDefaultDashboard(replaceDefaultDashboardOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(replaceDefaultDashboardResponse).ToNot(BeNil())
		})
	})

	Describe(`AssignDashboardFolder - Assign a dashboard to a folder`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`AssignDashboardFolder(assignDashboardFolderOptions *AssignDashboardFolderOptions)`, func() {
			assignDashboardFolderOptions := &logsv0.AssignDashboardFolderOptions{
				DashboardID: &dashboardIdLink,
				FolderID:    core.StringPtr(folderIdLink.String()),
			}

			assignDashboardFolderResponse, response, err := logsService.AssignDashboardFolder(assignDashboardFolderOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(assignDashboardFolderResponse).ToNot(BeNil())
		})
	})

	Describe(`ListDashboardFolders - List all dashboard folders`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListDashboardFolders(listDashboardFoldersOptions *ListDashboardFoldersOptions)`, func() {
			listDashboardFoldersOptions := &logsv0.ListDashboardFoldersOptions{}

			dashboardFolderCollection, response, err := logsService.ListDashboardFolders(listDashboardFoldersOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(dashboardFolderCollection).ToNot(BeNil())
		})
	})

	Describe(`ReplaceDashboardFolder - Update a dashboard folder`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ReplaceDashboardFolder(replaceDashboardFolderOptions *ReplaceDashboardFolderOptions)`, func() {
			replaceDashboardFolderOptions := &logsv0.ReplaceDashboardFolderOptions{
				FolderID: &folderIdLink,
				Name:     core.StringPtr("My Folder"),
			}

			dashboardFolder, response, err := logsService.ReplaceDashboardFolder(replaceDashboardFolderOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(dashboardFolder).ToNot(BeNil())
		})
	})

	Describe(`ListE2m - Lists event to metrics definitions`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListE2m(listE2mOptions *ListE2mOptions)`, func() {
			listE2mOptions := &logsv0.ListE2mOptions{}

			event2MetricCollection, response, err := logsService.ListE2m(listE2mOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(event2MetricCollection).ToNot(BeNil())
		})
	})

	Describe(`GetE2m - Gets event to metrics definitions by id`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetE2m(getE2mOptions *GetE2mOptions)`, func() {
			getE2mOptions := &logsv0.GetE2mOptions{
				ID: core.StringPtr(events2MetricsIdLink.String()),
			}

			event2Metric, response, err := logsService.GetE2m(getE2mOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(event2Metric).ToNot(BeNil())
		})
	})

	Describe(`ReplaceE2m - Updates event to metrics definitions`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ReplaceE2m(replaceE2mOptions *ReplaceE2mOptions)`, func() {
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

			replaceE2mOptions := &logsv0.ReplaceE2mOptions{
				ID:                    core.StringPtr(events2MetricsIdLink.String()),
				Event2MetricPrototype: event2MetricPrototypeModel,
			}

			event2Metric, response, err := logsService.ReplaceE2m(replaceE2mOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(event2Metric).ToNot(BeNil())
		})
	})

	Describe(`ListViews - Lists all company public views`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListViews(listViewsOptions *ListViewsOptions)`, func() {
			listViewsOptions := &logsv0.ListViewsOptions{}

			viewCollection, response, err := logsService.ListViews(listViewsOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(viewCollection).ToNot(BeNil())
		})
	})

	Describe(`GetView - Gets a view by ID`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetView(getViewOptions *GetViewOptions)`, func() {
			getViewOptions := &logsv0.GetViewOptions{
				ID: &viewIdLink,
			}

			view, response, err := logsService.GetView(getViewOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(view).ToNot(BeNil())
		})
	})

	Describe(`ReplaceView - Replaces an existing view`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ReplaceView(replaceViewOptions *ReplaceViewOptions)`, func() {
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

			replaceViewOptions := &logsv0.ReplaceViewOptions{
				ID:            &viewIdLink,
				Name:          core.StringPtr("Logs view"),
				SearchQuery:   apisViewsV1SearchQueryModel,
				TimeSelection: apisViewsV1TimeSelectionModel,
				Filters:       apisViewsV1SelectedFiltersModel,
			}

			view, response, err := logsService.ReplaceView(replaceViewOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(view).ToNot(BeNil())
		})
	})

	Describe(`ListViewFolders - List view's folders`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListViewFolders(listViewFoldersOptions *ListViewFoldersOptions)`, func() {
			listViewFoldersOptions := &logsv0.ListViewFoldersOptions{}

			viewFolderCollection, response, err := logsService.ListViewFolders(listViewFoldersOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(viewFolderCollection).ToNot(BeNil())
		})
	})

	Describe(`GetViewFolder - Get view folder`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetViewFolder(getViewFolderOptions *GetViewFolderOptions)`, func() {
			getViewFolderOptions := &logsv0.GetViewFolderOptions{
				ID: &viewFolderIdLink,
			}

			viewFolder, response, err := logsService.GetViewFolder(getViewFolderOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(viewFolder).ToNot(BeNil())
		})
	})

	Describe(`ReplaceViewFolder - Replaces an existing view folder`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ReplaceViewFolder(replaceViewFolderOptions *ReplaceViewFolderOptions)`, func() {
			replaceViewFolderOptions := &logsv0.ReplaceViewFolderOptions{
				ID:   &viewFolderIdLink,
				Name: core.StringPtr("My Folder"),
			}

			viewFolder, response, err := logsService.ReplaceViewFolder(replaceViewFolderOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(viewFolder).ToNot(BeNil())
		})
	})

	Describe(`GetEnrichments - List all enrichments`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetEnrichments(getEnrichmentsOptions *GetEnrichmentsOptions)`, func() {
			getEnrichmentsOptions := &logsv0.GetEnrichmentsOptions{}

			entrichmentCollection, response, err := logsService.GetEnrichments(getEnrichmentsOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(entrichmentCollection).ToNot(BeNil())
		})
	})

	Describe(`GetDataUsageMetricsExportStatus - Get data usage metrics export status`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetDataUsageMetricsExportStatus(getDataUsageMetricsExportStatusOptions *GetDataUsageMetricsExportStatusOptions)`, func() {
			getDataUsageMetricsExportStatusOptions := &logsv0.GetDataUsageMetricsExportStatusOptions{}

			dataUsageMetricsExportStatus, response, err := logsService.GetDataUsageMetricsExportStatus(getDataUsageMetricsExportStatusOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(dataUsageMetricsExportStatus).ToNot(BeNil())
		})
	})

	Describe(`UpdateDataUsageMetricsExportStatus - Update data usage metrics export status`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateDataUsageMetricsExportStatus(updateDataUsageMetricsExportStatusOptions *UpdateDataUsageMetricsExportStatusOptions)`, func() {
			updateDataUsageMetricsExportStatusOptions := &logsv0.UpdateDataUsageMetricsExportStatusOptions{
				Enabled: core.BoolPtr(true),
			}

			dataUsageMetricsExportStatus, response, err := logsService.UpdateDataUsageMetricsExportStatus(updateDataUsageMetricsExportStatusOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(dataUsageMetricsExportStatus).ToNot(BeNil())
		})
	})

	Describe(`UpdateDataAccessRule - Update a Data Access Rule`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateDataAccessRule(updateDataAccessRuleOptions *UpdateDataAccessRuleOptions)`, func() {
			dataAccessRuleFilterModel := &logsv0.DataAccessRuleFilter{
				EntityType: core.StringPtr("logs"),
				Expression: core.StringPtr("<v1> foo == 'bar'"),
			}

			updateDataAccessRuleOptions := &logsv0.UpdateDataAccessRuleOptions{
				ID:                &dataAccessRuleIdLink,
				DisplayName:       core.StringPtr("Test Data Access Rule"),
				Filters:           []logsv0.DataAccessRuleFilter{*dataAccessRuleFilterModel},
				DefaultExpression: core.StringPtr("<v1>true"),
				Description:       core.StringPtr("Data Access Rule intended for testing"),
			}

			dataAccessRule, response, err := logsService.UpdateDataAccessRule(updateDataAccessRuleOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(dataAccessRule).ToNot(BeNil())
		})
	})

	Describe(`ListDataAccessRules - List service instance's Data Access Rules with provided ids`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ListDataAccessRules(listDataAccessRulesOptions *ListDataAccessRulesOptions)`, func() {
			listDataAccessRulesOptions := &logsv0.ListDataAccessRulesOptions{
				ID: []strfmt.UUID{"4f966911-4bda-407e-b069-477394effa59"},
			}

			dataAccessRuleCollection, response, err := logsService.ListDataAccessRules(listDataAccessRulesOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(dataAccessRuleCollection).ToNot(BeNil())
		})
	})

	Describe(`DeleteAlert - Delete an alert`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteAlert(deleteAlertOptions *DeleteAlertOptions)`, func() {
			deleteAlertOptions := &logsv0.DeleteAlertOptions{
				ID: &alertIdLink,
			}

			response, err := logsService.DeleteAlert(deleteAlertOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`DeleteRuleGroup - Deletes rule group by groupid`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteRuleGroup(deleteRuleGroupOptions *DeleteRuleGroupOptions)`, func() {
			deleteRuleGroupOptions := &logsv0.DeleteRuleGroupOptions{
				GroupID: &ruleGroupIdLink,
			}

			response, err := logsService.DeleteRuleGroup(deleteRuleGroupOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`DeleteOutgoingWebhook - Delete an Outbound Integration`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteOutgoingWebhook(deleteOutgoingWebhookOptions *DeleteOutgoingWebhookOptions)`, func() {
			deleteOutgoingWebhookOptions := &logsv0.DeleteOutgoingWebhookOptions{
				ID: &outgoingWebhookIdLink,
			}

			response, err := logsService.DeleteOutgoingWebhook(deleteOutgoingWebhookOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`DeletePolicy - Deletes an existing policy`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeletePolicy(deletePolicyOptions *DeletePolicyOptions)`, func() {
			deletePolicyOptions := &logsv0.DeletePolicyOptions{
				ID: &policyIdLink,
			}

			response, err := logsService.DeletePolicy(deletePolicyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`UnpinDashboard - Remove dashboard to the favorite folder`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UnpinDashboard(unpinDashboardOptions *UnpinDashboardOptions)`, func() {
			unpinDashboardOptions := &logsv0.UnpinDashboardOptions{
				DashboardID: &dashboardIdLink,
			}

			response, err := logsService.UnpinDashboard(unpinDashboardOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`DeleteDashboard - Deletes an existing dashboard`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteDashboard(deleteDashboardOptions *DeleteDashboardOptions)`, func() {
			deleteDashboardOptions := &logsv0.DeleteDashboardOptions{
				DashboardID: &dashboardIdLink,
			}

			response, err := logsService.DeleteDashboard(deleteDashboardOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`DeleteDashboardFolder - Delete a dashboard folder`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteDashboardFolder(deleteDashboardFolderOptions *DeleteDashboardFolderOptions)`, func() {
			deleteDashboardFolderOptions := &logsv0.DeleteDashboardFolderOptions{
				FolderID: &folderIdLink,
			}

			response, err := logsService.DeleteDashboardFolder(deleteDashboardFolderOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`DeleteE2m - Deletes event to metrics definitions by id`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteE2m(deleteE2mOptions *DeleteE2mOptions)`, func() {
			deleteE2mOptions := &logsv0.DeleteE2mOptions{
				ID: core.StringPtr(events2MetricsIdLink.String()),
			}

			response, err := logsService.DeleteE2m(deleteE2mOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`DeleteView - Deletes a view by ID`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteView(deleteViewOptions *DeleteViewOptions)`, func() {
			deleteViewOptions := &logsv0.DeleteViewOptions{
				ID: &viewIdLink,
			}

			response, err := logsService.DeleteView(deleteViewOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`DeleteViewFolder - Deletes a view folder by ID`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteViewFolder(deleteViewFolderOptions *DeleteViewFolderOptions)`, func() {
			deleteViewFolderOptions := &logsv0.DeleteViewFolderOptions{
				ID: &viewFolderIdLink,
			}

			response, err := logsService.DeleteViewFolder(deleteViewFolderOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`DeleteDataAccessRule - Delete a Data Access Rule`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteDataAccessRule(deleteDataAccessRuleOptions *DeleteDataAccessRuleOptions)`, func() {
			deleteDataAccessRuleOptions := &logsv0.DeleteDataAccessRuleOptions{
				ID: &dataAccessRuleIdLink,
			}

			response, err := logsService.DeleteDataAccessRule(deleteDataAccessRuleOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`RemoveEnrichments - Delete enrichments`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`RemoveEnrichments(removeEnrichmentsOptions *RemoveEnrichmentsOptions)`, func() {
			removeEnrichmentsOptions := &logsv0.RemoveEnrichmentsOptions{
				ID: &encrichmentsIdLink,
			}

			response, err := logsService.RemoveEnrichments(removeEnrichmentsOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})
})

//
// Utility functions are declared in the unit test file
//
