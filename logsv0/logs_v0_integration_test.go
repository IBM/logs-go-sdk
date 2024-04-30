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

	"math/rand"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/logs-go-sdk/logsv0"
	"github.com/go-openapi/strfmt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

/**
 * This file contains an integration test for the logsv0 package.
 *
 * Notes:
 *
 * The integration test will automatically skip tests if the required config file is not available.
 * The commented part of the paylod in this file means that the generated payload from the openapi-sdk tool didn't work
 * and those parts of the payload is commented to construct a valid payload.
 */

func getRandomName() string {
	number := rand.Intn(1000)
	return fmt.Sprintf("test-%d", number)
}

var _ = Describe(`LogsV0 Integration Tests`, func() {
	const (
		externalConfigFile = "../logs.env"
	)

	var (
		err                          error
		logsService                  *logsv0.LogsV0
		serviceURL                   string
		eventNotificationsInstanceID string
		config                       map[string]string
		alertID                      *strfmt.UUID
		// ruleGroupID                  *strfmt.UUID
		policyID        *strfmt.UUID
		event2MetricsID *strfmt.UUID
		viewID          int64
		viewFolderID    *strfmt.UUID
		// outgoingWebhookID            string
		nameForPayload = getRandomName()
		dashboardID    string
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

			eventNotificationsInstanceID = config["IBM_EVENT_NOTIFICATIONS_INSTANCE_ID"]
			if eventNotificationsInstanceID == "" {
				Skip("Unable to load IBM_EVENT_NOTIFICATIONS_INSTANCE_ID configuration property, skipping tests")
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
			logsService.EnableRetries(2, 2*time.Second)
		})
	})

	Describe(`CreateAlert - Create Alert`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateAlert(createAlertOptions *CreateAlertOptions)`, func() {
			// alertsV1MetricAlertConditionParametersModel := &logsv0.AlertsV1MetricAlertConditionParameters{
			// 	MetricField:                core.StringPtr("testString"),
			// 	MetricSource:               core.StringPtr("logs2metrics_or_unspecified"),
			// 	ArithmeticOperator:         core.StringPtr("avg_or_unspecified"),
			// 	ArithmeticOperatorModifier: core.Int64Ptr(int64(0)),
			// 	SampleThresholdPercentage:  core.Int64Ptr(int64(0)),
			// 	NonNullPercentage:          core.Int64Ptr(int64(0)),
			// 	SwapNullValues:             core.BoolPtr(true),
			// }

			// alertsV1MetricAlertPromqlConditionParametersModel := &logsv0.AlertsV1MetricAlertPromqlConditionParameters{
			// PromqlText:                 core.StringPtr("testString"),
			// ArithmeticOperatorModifier: core.Int64Ptr(int64(0)),
			// SampleThresholdPercentage:  core.Int64Ptr(int64(0)),
			// NonNullPercentage:          core.Int64Ptr(int64(0)),
			// SwapNullValues:             core.BoolPtr(true),
			// }

			// alertsV1RelatedExtendedDataModel := &logsv0.AlertsV1RelatedExtendedData{
			// 	CleanupDeadmanDuration: core.StringPtr("cleanup_deadman_duration_never_or_unspecified"),
			// 	ShouldTriggerDeadman:   core.BoolPtr(true),
			// }

			alertsV2ConditionParametersModel := &logsv0.AlertsV2ConditionParameters{
				Threshold: core.Float64Ptr(float64(1.0)),
				Timeframe: core.StringPtr("timeframe_10_min"),
				GroupBy:   []string{"coralogix.metadata.applicationName"},
				// MetricAlertParameters: alertsV1MetricAlertConditionParametersModel,
				// MetricAlertPromqlParameters:       alertsV1MetricAlertPromqlConditionParametersModel,
				IgnoreInfinity:    core.BoolPtr(true),
				RelativeTimeframe: core.StringPtr("hour_or_unspecified"),
				CardinalityFields: []string{},
				// RelatedExtendedData:               alertsV1RelatedExtendedDataModel,
			}

			alertsV2MoreThanConditionModel := &logsv0.AlertsV2MoreThanCondition{
				Parameters:       alertsV2ConditionParametersModel,
				EvaluationWindow: core.StringPtr("rolling_or_unspecified"),
			}

			alertsV2AlertConditionModel := &logsv0.AlertsV2AlertConditionConditionMoreThan{
				MoreThan: alertsV2MoreThanConditionModel,
			}

			// alertsV2AlertNotificationModel := &logsv0.AlertsV2AlertNotificationIntegrationTypeIntegrationID{
			// 	RetriggeringPeriodSeconds: core.Int64Ptr(int64(0)),
			// 	NotifyOn:                  core.StringPtr("triggered_only"),
			// 	IntegrationID:             core.Int64Ptr(int64(0)),
			// }

			alertsV2AlertNotificationGroupsModel := &logsv0.AlertsV2AlertNotificationGroups{
				GroupByFields: []string{"coralogix.metadata.applicationName"},
				//Notifications: []logsv0.AlertsV2AlertNotificationIntf{alertsV2AlertNotificationModel},
				Notifications: []logsv0.AlertsV2AlertNotificationIntf{},
			}

			// alertsV1DateModel := &logsv0.AlertsV1Date{
			// 	Year:  core.Int64Ptr(int64(2024)),
			// 	Month: core.Int64Ptr(int64(12)),
			// 	Day:   core.Int64Ptr(int64(10)),
			// }

			// alertsV2ShowInInsightModel := &logsv0.AlertsV2ShowInInsight{
			// 	RetriggeringPeriodSeconds: core.Int64Ptr(int64(0)),
			// 	NotifyOn:                  core.StringPtr("triggered_only"),
			// }

			alertsV1AlertFiltersMetadataFiltersModel := &logsv0.AlertsV1AlertFiltersMetadataFilters{
				Categories:   []string{"testString"},
				Applications: []string{"testString"},
				Subsystems:   []string{"testString"},
				Computers:    []string{"testString"},
				Classes:      []string{"testString"},
				Methods:      []string{"testString"},
				IpAddresses:  []string{"testString"},
			}

			alertsV1AlertFiltersRatioAlertModel := &logsv0.AlertsV1AlertFiltersRatioAlert{
				Alias:        core.StringPtr("testString"),
				Text:         core.StringPtr("testString"),
				Severities:   []string{"debug_or_unspecified"},
				Applications: []string{"testString"},
				Subsystems:   []string{"testString"},
				GroupBy:      []string{"testString"},
			}

			alertsV1AlertFiltersModel := &logsv0.AlertsV1AlertFilters{
				Severities:  []string{"info"},
				Metadata:    alertsV1AlertFiltersMetadataFiltersModel,
				Alias:       core.StringPtr("testString"),
				Text:        core.StringPtr("initiator.id.keyword:/iam-ServiceId-10820fd6-c3fe-414e-8fd5-44ce95f7d34d.*/ AND action.keyword:/cloud-object-storage.object.create.*/ AND target.id.keyword:/crn:v1:bluemix:public:cloud-object-storage:global:a\\/81de6380e6232019c6567c9c8de6dece:69002255-e226-424e-b6c7-23c887fdb8bf:bucket:at-frankfurt.*/"),
				RatioAlerts: []logsv0.AlertsV1AlertFiltersRatioAlert{*alertsV1AlertFiltersRatioAlertModel},
				FilterType:  core.StringPtr("text_or_unspecified"),
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

			// alertsV1MetaLabelModel := &logsv0.AlertsV1MetaLabel{
			// 	Key:   core.StringPtr("testString"),
			// 	Value: core.StringPtr("testString"),
			// }

			// alertsV1FiltersModel := &logsv0.AlertsV1Filters{
			// 	Values:   []string{"testString"},
			// 	Operator: core.StringPtr("testString"),
			// }

			// alertsV1FilterDataModel := &logsv0.AlertsV1FilterData{
			// 	Field:   core.StringPtr("testString"),
			// 	Filters: []logsv0.AlertsV1Filters{*alertsV1FiltersModel},
			// }

			// alertsV1TracingAlertModel := &logsv0.AlertsV1TracingAlert{
			// 	ConditionLatency: core.Int64Ptr(int64(0)),
			// 	FieldFilters:     []logsv0.AlertsV1FilterData{*alertsV1FilterDataModel},
			// 	TagFilters:       []logsv0.AlertsV1FilterData{*alertsV1FilterDataModel},
			// }

			alertsV2AlertIncidentSettingsModel := &logsv0.AlertsV2AlertIncidentSettings{
				RetriggeringPeriodSeconds: core.Int64Ptr(int64(300)),
				NotifyOn:                  core.StringPtr("triggered_only"),
				UseAsNotificationSettings: core.BoolPtr(true),
			}

			createAlertOptions := &logsv0.CreateAlertOptions{
				Name:               core.StringPtr("nameForPayload"),
				IsActive:           core.BoolPtr(true),
				Condition:          alertsV2AlertConditionModel,
				NotificationGroups: []logsv0.AlertsV2AlertNotificationGroups{*alertsV2AlertNotificationGroupsModel},
				Description:        core.StringPtr("Test alert to check OpenAPI"),
				Severity:           core.StringPtr("info_or_unspecified"),
				// Expiration:                 alertsV1DateModel,
				// ShowInInsight:              alertsV2ShowInInsightModel,
				Filters:    alertsV1AlertFiltersModel,
				ActiveWhen: alertsV1AlertActiveWhenModel,
				// NotificationPayloadFilters: []string{"testString"},
				// MetaLabels:                 []logsv0.AlertsV1MetaLabel{*alertsV1MetaLabelModel},
				MetaLabelsStrings: []string{},
				// TracingAlert:               alertsV1TracingAlertModel,
				IncidentSettings: alertsV2AlertIncidentSettingsModel,
			}

			alert, response, err := logsService.CreateAlert(createAlertOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(alert).ToNot(BeNil())
			alertID = alert.ID
		})
	})

	Describe(`UpdateAlert - Update Alert`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdateAlert(updateAlertOptions *UpdateAlertOptions)`, func() {
			// alertsV1MetricAlertConditionParametersModel := &logsv0.AlertsV1MetricAlertConditionParameters{
			// 	MetricField:                core.StringPtr("testString"),
			// 	MetricSource:               core.StringPtr("logs2metrics_or_unspecified"),
			// 	ArithmeticOperator:         core.StringPtr("avg_or_unspecified"),
			// 	ArithmeticOperatorModifier: core.Int64Ptr(int64(0)),
			// 	SampleThresholdPercentage:  core.Int64Ptr(int64(0)),
			// 	NonNullPercentage:          core.Int64Ptr(int64(0)),
			// 	SwapNullValues:             core.BoolPtr(true),
			// }

			// alertsV1MetricAlertPromqlConditionParametersModel := &logsv0.AlertsV1MetricAlertPromqlConditionParameters{
			// PromqlText:                 core.StringPtr("testString"),
			// ArithmeticOperatorModifier: core.Int64Ptr(int64(0)),
			// SampleThresholdPercentage:  core.Int64Ptr(int64(0)),
			// NonNullPercentage:          core.Int64Ptr(int64(0)),
			// SwapNullValues:             core.BoolPtr(true),
			// }

			// alertsV1RelatedExtendedDataModel := &logsv0.AlertsV1RelatedExtendedData{
			// 	CleanupDeadmanDuration: core.StringPtr("cleanup_deadman_duration_never_or_unspecified"),
			// 	ShouldTriggerDeadman:   core.BoolPtr(true),
			// }

			alertsV2ConditionParametersModel := &logsv0.AlertsV2ConditionParameters{
				Threshold: core.Float64Ptr(float64(1.0)),
				Timeframe: core.StringPtr("timeframe_10_min"),
				GroupBy:   []string{"coralogix.metadata.applicationName"},
				// MetricAlertParameters: alertsV1MetricAlertConditionParametersModel,
				// MetricAlertPromqlParameters:       alertsV1MetricAlertPromqlConditionParametersModel,
				IgnoreInfinity:    core.BoolPtr(true),
				RelativeTimeframe: core.StringPtr("hour_or_unspecified"),
				CardinalityFields: []string{},
				// RelatedExtendedData:               alertsV1RelatedExtendedDataModel,
			}

			alertsV2MoreThanConditionModel := &logsv0.AlertsV2MoreThanCondition{
				Parameters:       alertsV2ConditionParametersModel,
				EvaluationWindow: core.StringPtr("rolling_or_unspecified"),
			}

			alertsV2AlertConditionModel := &logsv0.AlertsV2AlertConditionConditionMoreThan{
				MoreThan: alertsV2MoreThanConditionModel,
			}

			// alertsV2AlertNotificationModel := &logsv0.AlertsV2AlertNotificationIntegrationTypeIntegrationID{
			// 	RetriggeringPeriodSeconds: core.Int64Ptr(int64(0)),
			// 	NotifyOn:                  core.StringPtr("triggered_only"),
			// 	IntegrationID:             core.Int64Ptr(int64(0)),
			// }

			alertsV2AlertNotificationGroupsModel := &logsv0.AlertsV2AlertNotificationGroups{
				GroupByFields: []string{"coralogix.metadata.applicationName"},
				//Notifications: []logsv0.AlertsV2AlertNotificationIntf{alertsV2AlertNotificationModel},
				Notifications: []logsv0.AlertsV2AlertNotificationIntf{},
			}

			// alertsV1DateModel := &logsv0.AlertsV1Date{
			// 	Year:  core.Int64Ptr(int64(2024)),
			// 	Month: core.Int64Ptr(int64(12)),
			// 	Day:   core.Int64Ptr(int64(10)),
			// }

			// alertsV2ShowInInsightModel := &logsv0.AlertsV2ShowInInsight{
			// 	RetriggeringPeriodSeconds: core.Int64Ptr(int64(0)),
			// 	NotifyOn:                  core.StringPtr("triggered_only"),
			// }

			alertsV1AlertFiltersMetadataFiltersModel := &logsv0.AlertsV1AlertFiltersMetadataFilters{
				Categories:   []string{"testString"},
				Applications: []string{"testString"},
				Subsystems:   []string{"testString"},
				Computers:    []string{"testString"},
				Classes:      []string{"testString"},
				Methods:      []string{"testString"},
				IpAddresses:  []string{"testString"},
			}

			alertsV1AlertFiltersRatioAlertModel := &logsv0.AlertsV1AlertFiltersRatioAlert{
				Alias:        core.StringPtr("testString"),
				Text:         core.StringPtr("testString"),
				Severities:   []string{"debug_or_unspecified"},
				Applications: []string{"testString"},
				Subsystems:   []string{"testString"},
				GroupBy:      []string{"testString"},
			}

			alertsV1AlertFiltersModel := &logsv0.AlertsV1AlertFilters{
				Severities:  []string{"info"},
				Metadata:    alertsV1AlertFiltersMetadataFiltersModel,
				Alias:       core.StringPtr("testString"),
				Text:        core.StringPtr("initiator.id.keyword:/iam-ServiceId-10820fd6-c3fe-414e-8fd5-44ce95f7d34d.*/ AND action.keyword:/cloud-object-storage.object.create.*/ AND target.id.keyword:/crn:v1:bluemix:public:cloud-object-storage:global:a\\/81de6380e6232019c6567c9c8de6dece:69002255-e226-424e-b6c7-23c887fdb8bf:bucket:at-frankfurt.*/"),
				RatioAlerts: []logsv0.AlertsV1AlertFiltersRatioAlert{*alertsV1AlertFiltersRatioAlertModel},
				FilterType:  core.StringPtr("text_or_unspecified"),
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

			// alertsV1MetaLabelModel := &logsv0.AlertsV1MetaLabel{
			// 	Key:   core.StringPtr("testString"),
			// 	Value: core.StringPtr("testString"),
			// }

			// alertsV1FiltersModel := &logsv0.AlertsV1Filters{
			// 	Values:   []string{"testString"},
			// 	Operator: core.StringPtr("testString"),
			// }

			// alertsV1FilterDataModel := &logsv0.AlertsV1FilterData{
			// 	Field:   core.StringPtr("testString"),
			// 	Filters: []logsv0.AlertsV1Filters{*alertsV1FiltersModel},
			// }

			// alertsV1TracingAlertModel := &logsv0.AlertsV1TracingAlert{
			// 	ConditionLatency: core.Int64Ptr(int64(0)),
			// 	FieldFilters:     []logsv0.AlertsV1FilterData{*alertsV1FilterDataModel},
			// 	TagFilters:       []logsv0.AlertsV1FilterData{*alertsV1FilterDataModel},
			// }

			alertsV2AlertIncidentSettingsModel := &logsv0.AlertsV2AlertIncidentSettings{
				RetriggeringPeriodSeconds: core.Int64Ptr(int64(300)),
				NotifyOn:                  core.StringPtr("triggered_only"),
				UseAsNotificationSettings: core.BoolPtr(true),
			}

			description := "Test alert updated to check OpenAPI"
			updateAlertOptions := &logsv0.UpdateAlertOptions{
				ID:                 alertID,
				Name:               core.StringPtr(nameForPayload),
				IsActive:           core.BoolPtr(true),
				Condition:          alertsV2AlertConditionModel,
				NotificationGroups: []logsv0.AlertsV2AlertNotificationGroups{*alertsV2AlertNotificationGroupsModel},
				Description:        core.StringPtr(description),
				Severity:           core.StringPtr("info_or_unspecified"),
				// Expiration:                 alertsV1DateModel,
				// ShowInInsight:              alertsV2ShowInInsightModel,
				Filters:    alertsV1AlertFiltersModel,
				ActiveWhen: alertsV1AlertActiveWhenModel,
				// NotificationPayloadFilters: []string{"testString"},
				// MetaLabels:                 []logsv0.AlertsV1MetaLabel{*alertsV1MetaLabelModel},
				MetaLabelsStrings: []string{},
				// TracingAlert:               alertsV1TracingAlertModel,
				IncidentSettings: alertsV2AlertIncidentSettingsModel,
			}
			alert, response, err := logsService.UpdateAlert(updateAlertOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(alert).ToNot(BeNil())
			Expect(*(alert.Description)).To(Equal(description))
		})
	})

	// Describe(`GetAlerts - Get Alerts`, func() {
	// 	BeforeEach(func() {
	// 		shouldSkipTest()
	// 	})
	// 	It(`GetAlerts(getAlertsOptions *GetAlertsOptions)`, func() {
	// 		getAlertsOptions := &logsv0.GetAlertsOptions{}

	// 		alertCollection, response, err := logsService.GetAlerts(getAlertsOptions)
	// 		Expect(err).To(BeNil())
	// 		Expect(response.StatusCode).To(Equal(200))
	// 		Expect(alertCollection).ToNot(BeNil())
	// 	})
	// })

	Describe(`GetAlerts - Get Alerts`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetAlerts(getAlertsOptions *GetAlertsOptions)`, func() {
			getAlertsOptions := &logsv0.GetAlertOptions{
				ID: alertID,
			}

			alert, response, err := logsService.GetAlert(getAlertsOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(alert).ToNot(BeNil())
		})
	})

	Describe(`DeleteAlert - Delete Alert`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteAlert(deleteAlertOptions *DeleteAlertOptions)`, func() {
			deleteAlertOptions := &logsv0.DeleteAlertOptions{
				ID: alertID,
			}

			response, err := logsService.DeleteAlert(deleteAlertOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	// Since, creator field is removed, we are not passing the creator field in the payload
	// but the api is still failing expecting the creator field.
	// we are skipping this test until the issue is fixed
	// Describe(`CreateRuleGroup - Create Rule Group`, func() {
	// 	BeforeEach(func() {
	// 		shouldSkipTest()
	// 	})
	// 	It(`CreateRuleGroup(createRuleGroupOptions *CreateRuleGroupOptions)`, func() {
	// 		rulesV1SubsystemNameConstraintModel := &logsv0.RulesV1SubsystemNameConstraint{
	// 			Value: core.StringPtr("mysql-cloudwatch"),
	// 		}

	// 		rulesV1RuleMatcherModel := &logsv0.RulesV1RuleMatcherConstraintSubsystemName{
	// 			SubsystemName: rulesV1SubsystemNameConstraintModel,
	// 		}

	// 		rulesV1ParseParametersModel := &logsv0.RulesV1ParseParameters{
	// 			DestinationField: core.StringPtr("text"),
	// 			Rule:             core.StringPtr("(?P<timestamp>[^,]+),(?P<hostname>[^,]+),(?P<username>[^,]+),(?P<ip>[^,]+),(?P<connectionId>[0-9]+),(?P<queryId>[0-9]+),(?P<operation>[^,]+),(?P<database>[^,]+),?(?P<object>.*)?,(?P<returnCode>[0-9]+)"),
	// 		}

	// 		rulesV1RuleParametersModel := &logsv0.RulesV1RuleParametersRuleParametersParseParameters{
	// 			ParseParameters: rulesV1ParseParametersModel,
	// 		}

	// 		rulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRuleModel := &logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRule{
	// 			Name:        core.StringPtr("mysql-parse"),
	// 			Description: core.StringPtr("mysql-parse"),
	// 			SourceField: core.StringPtr("text"),
	// 			Parameters:  rulesV1RuleParametersModel,
	// 			Enabled:     core.BoolPtr(true),
	// 			Order:       core.Int64Ptr(int64(1)),
	// 		}

	// 		rulesV1CreateRuleGroupRequestCreateRuleSubgroupModel := &logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroup{
	// 			Rules:   []logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRule{*rulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRuleModel},
	// 			Enabled: core.BoolPtr(true),
	// 			Order:   core.Int64Ptr(int64(1)),
	// 		}

	// 		// rulesV1TeamIdModel := &logsv0.RulesV1TeamID{
	// 		// 	ID: core.Int64Ptr(int64(0)),
	// 		// }

	// 		createRuleGroupOptions := &logsv0.CreateRuleGroupOptions{
	// 			Name:          core.StringPtr(nameForPayload),
	// 			Description:   core.StringPtr("mysql-cloudwatch audit logs parser"),
	// 			Enabled:       core.BoolPtr(true),
	// 			RuleMatchers:  []logsv0.RulesV1RuleMatcherIntf{rulesV1RuleMatcherModel},
	// 			RuleSubgroups: []logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroup{*rulesV1CreateRuleGroupRequestCreateRuleSubgroupModel},
	// 			Order:         core.Int64Ptr(int64(39)),
	// 			// TeamID:              rulesV1TeamIdModel,
	// 		}

	// 		ruleGroup, response, err := logsService.CreateRuleGroup(createRuleGroupOptions)
	// 		Expect(err).To(BeNil())
	// 		Expect(response.StatusCode).To(Equal(201))
	// 		Expect(ruleGroup).ToNot(BeNil())
	// 		ruleGroupID = ruleGroup.ID
	// 	})
	// })

	// Describe(`UpdateRuleGroup - Update Rule Group`, func() {
	// 	BeforeEach(func() {
	// 		shouldSkipTest()
	// 	})
	// 	It(`UpdateRuleGroup(updateRuleGroupOptions *UpdateRuleGroupOptions)`, func() {
	// 		rulesV1SubsystemNameConstraintModel := &logsv0.RulesV1SubsystemNameConstraint{
	// 			Value: core.StringPtr("mysql-cloudwatch"),
	// 		}

	// 		rulesV1RuleMatcherModel := &logsv0.RulesV1RuleMatcherConstraintSubsystemName{
	// 			SubsystemName: rulesV1SubsystemNameConstraintModel,
	// 		}

	// 		rulesV1ParseParametersModel := &logsv0.RulesV1ParseParameters{
	// 			DestinationField: core.StringPtr("text"),
	// 			Rule:             core.StringPtr("(?P<timestamp>[^,]+),(?P<hostname>[^,]+),(?P<username>[^,]+),(?P<ip>[^,]+),(?P<connectionId>[0-9]+),(?P<queryId>[0-9]+),(?P<operation>[^,]+),(?P<database>[^,]+),?(?P<object>.*)?,(?P<returnCode>[0-9]+)"),
	// 		}

	// 		rulesV1RuleParametersModel := &logsv0.RulesV1RuleParametersRuleParametersParseParameters{
	// 			ParseParameters: rulesV1ParseParametersModel,
	// 		}

	// 		rulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRuleModel := &logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRule{
	// 			Name:        core.StringPtr("mysql-parse"),
	// 			Description: core.StringPtr("mysql-parse"),
	// 			SourceField: core.StringPtr("text"),
	// 			Parameters:  rulesV1RuleParametersModel,
	// 			Enabled:     core.BoolPtr(true),
	// 			Order:       core.Int64Ptr(int64(1)),
	// 		}

	// 		rulesV1CreateRuleGroupRequestCreateRuleSubgroupModel := &logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroup{
	// 			Rules:   []logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRule{*rulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRuleModel},
	// 			Enabled: core.BoolPtr(true),
	// 			Order:   core.Int64Ptr(int64(1)),
	// 		}

	// 		updateRuleGroupOptions := &logsv0.UpdateRuleGroupOptions{
	// 			GroupID:       ruleGroupID,
	// 			Name:          core.StringPtr(nameForPayload),
	// 			Description:   core.StringPtr("mysql-cloudwatch audit updated logs parser"),
	// 			Enabled:       core.BoolPtr(true),
	// 			RuleMatchers:  []logsv0.RulesV1RuleMatcherIntf{rulesV1RuleMatcherModel},
	// 			RuleSubgroups: []logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroup{*rulesV1CreateRuleGroupRequestCreateRuleSubgroupModel},
	// 			Order:         core.Int64Ptr(int64(39)),
	// 		}

	// 		ruleGroup, response, err := logsService.UpdateRuleGroup(updateRuleGroupOptions)
	// 		Expect(err).To(BeNil())
	// 		Expect(response.StatusCode).To(Equal(200))
	// 		Expect(ruleGroup).ToNot(BeNil())
	// 		Expect(*ruleGroup.Description).To(Equal("mysql-cloudwatch audit updated logs parser"))
	// 	})
	// })

	// Describe(`GetRuleGroup - Get Rule Group`, func() {
	// 	BeforeEach(func() {
	// 		shouldSkipTest()
	// 	})
	// 	It(`GetRuleGroup(getRuleGroupOptions *GetRuleGroupOptions)`, func() {
	// 		getRuleGroupOptions := &logsv0.GetRuleGroupOptions{
	// 			GroupID: ruleGroupID,
	// 		}

	// 		ruleGroup, response, err := logsService.GetRuleGroup(getRuleGroupOptions)
	// 		Expect(err).To(BeNil())
	// 		Expect(response.StatusCode).To(Equal(200))
	// 		Expect(ruleGroup).ToNot(BeNil())
	// 	})
	// })

	// Describe(`DeleteRuleGroup - Delete Rule Group`, func() {
	// 	BeforeEach(func() {
	// 		shouldSkipTest()
	// 	})
	// 	It(`DeleteRuleGroup(deleteRuleGroupOptions *DeleteRuleGroupOptions)`, func() {
	// 		deleteRuleGroupOptions := &logsv0.DeleteRuleGroupOptions{
	// 			GroupID: ruleGroupID,
	// 		}

	// 		response, err := logsService.DeleteRuleGroup(deleteRuleGroupOptions)
	// 		Expect(err).To(BeNil())
	// 		Expect(response.StatusCode).To(Equal(204))
	// 	})
	// })

	// TODO: enable this once webhook API is working
	// Describe(`CreateOutgoingWebhook - Create Outgoing Webhook`, func() {
	// 	BeforeEach(func() {
	// 		shouldSkipTest()
	// 	})
	// 	It(`CreateOutgoingWebhook(createOutgoingWebhookOptions *CreateOutgoingWebhookOptions)`, func() {
	// 		eventNotificationsInstanceIDUUID := strfmt.UUID(eventNotificationsInstanceID)
	// 		outgoingWebhooksV1IbmEventNotificationsConfigModel := &logsv0.OutgoingWebhooksV1IbmEventNotificationsConfig{
	// 			EventNotificationsInstanceID: &eventNotificationsInstanceIDUUID,
	// 			RegionID:                     core.StringPtr("us-south"),
	// 		}

	// 		outgoingWebhookPrototypeModel := &logsv0.OutgoingWebhookPrototypeOutgoingWebhooksV1OutgoingWebhookInputDataConfigIbmEventNotifications{
	// 			Type:                  core.StringPtr("ibm_event_notifications"),
	// 			Name:                  core.StringPtr("test-webhook"),
	// 			URL:                   core.StringPtr("testString"),
	// 			IbmEventNotifications: outgoingWebhooksV1IbmEventNotificationsConfigModel,
	// 		}

	// 		createOutgoingWebhookOptions := &logsv0.CreateOutgoingWebhookOptions{
	// 			OutgoingWebhookPrototype: outgoingWebhookPrototypeModel,
	// 		}

	// 		outgoingWebhook, response, err := logsService.CreateOutgoingWebhook(createOutgoingWebhookOptions)
	// 		Expect(err).To(BeNil())
	// 		Expect(response.StatusCode).To(Equal(201))
	// 		Expect(outgoingWebhook).ToNot(BeNil())

	// 		outgoingWebhookID = outgoingWebhook.(*logsv0.OutgoingWebhook).ID.String()
	// 	})
	// })

	// Describe(`UpdateOutgoingWebhook - Update Outgoing Webhook`, func() {
	// 	BeforeEach(func() {
	// 		shouldSkipTest()
	// 	})
	// 	It(`UpdateOutgoingWebhook(updateOutgoingWebhookOptions *UpdateOutgoingWebhookOptions)`, func() {
	// 		eventNotificationsInstanceIDUUID := strfmt.UUID(eventNotificationsInstanceID)
	// 		outgoingWebhooksV1IbmEventNotificationsConfigModel := &logsv0.OutgoingWebhooksV1IbmEventNotificationsConfig{
	// 			EventNotificationsInstanceID: &eventNotificationsInstanceIDUUID,
	// 			RegionID:                     core.StringPtr("us-south"),
	// 		}

	// 		outgoingWebhookPrototypeModel := &logsv0.OutgoingWebhookPrototypeOutgoingWebhooksV1OutgoingWebhookInputDataConfigIbmEventNotifications{
	// 			Type:                  core.StringPtr("ibm_event_notifications"),
	// 			Name:                  core.StringPtr("test-webhook"),
	// 			URL:                   core.StringPtr("testString"),
	// 			IbmEventNotifications: outgoingWebhooksV1IbmEventNotificationsConfigModel,
	// 		}

	// 		updateOutgoingWebhookOptions := &logsv0.UpdateOutgoingWebhookOptions{
	// 			ID:                       core.StringPtr(outgoingWebhookID),
	// 			OutgoingWebhookPrototype: outgoingWebhookPrototypeModel,
	// 		}

	// 		outgoingWebhook, response, err := logsService.UpdateOutgoingWebhook(updateOutgoingWebhookOptions)
	// 		Expect(err).To(BeNil())
	// 		Expect(response.StatusCode).To(Equal(200))
	// 		Expect(outgoingWebhook).ToNot(BeNil())
	// 	})
	// })

	// Describe(`ListOutgoingWebhooks - List Outgoing Webhooks`, func() {
	// 	BeforeEach(func() {
	// 		shouldSkipTest()
	// 	})
	// 	It(`ListOutgoingWebhooks(listOutgoingWebhooksOptions *ListOutgoingWebhooksOptions)`, func() {
	// 		listOutgoingWebhooksOptions := &logsv0.ListOutgoingWebhooksOptions{
	// 			Type: core.StringPtr("ibm_event_notifications"),
	// 		}

	// 		outgoingWebhookCollection, response, err := logsService.ListOutgoingWebhooks(listOutgoingWebhooksOptions)
	// 		Expect(err).To(BeNil())
	// 		Expect(response.StatusCode).To(Equal(200))
	// 		Expect(outgoingWebhookCollection).ToNot(BeNil())
	// 	})
	// })

	// Describe(`GetOutgoingWebhook - Get Outgoing Webhook`, func() {
	// 	BeforeEach(func() {
	// 		shouldSkipTest()
	// 	})
	// 	It(`GetOutgoingWebhook(getOutgoingWebhookOptions *GetOutgoingWebhookOptions)`, func() {
	// 		getOutgoingWebhookOptions := &logsv0.GetOutgoingWebhookOptions{
	// 			ID: core.StringPtr(outgoingWebhookID),
	// 		}

	// 		outgoingWebhook, response, err := logsService.GetOutgoingWebhook(getOutgoingWebhookOptions)
	// 		Expect(err).To(BeNil())
	// 		Expect(response.StatusCode).To(Equal(200))
	// 		Expect(outgoingWebhook).ToNot(BeNil())
	// 	})
	// })

	// Describe(`DeleteOutgoingWebhook - Delete Outgoing Webhook`, func() {
	// 	BeforeEach(func() {
	// 		shouldSkipTest()
	// 	})
	// 	It(`DeleteOutgoingWebhook(deleteOutgoingWebhookOptions *DeleteOutgoingWebhookOptions)`, func() {
	// 		deleteOutgoingWebhookOptions := &logsv0.DeleteOutgoingWebhookOptions{
	// 			ID: core.StringPtr(outgoingWebhookID),
	// 		}

	// 		response, err := logsService.DeleteOutgoingWebhook(deleteOutgoingWebhookOptions)
	// 		Expect(err).To(BeNil())
	// 		Expect(response.StatusCode).To(Equal(204))
	// 	})
	// })

	Describe(`CreatePolicy - Create Policy`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreatePolicy(createPolicyOptions *CreatePolicyOptions)`, func() {
			qoutaRuleModel := &logsv0.QuotaV1Rule{
				RuleTypeID: core.StringPtr("is"),
				Name:       core.StringPtr("app"),
			}

			// quotaV1ArchiveRetentionModel := &logsv0.QuotaV1ArchiveRetention{
			// 	ID: core.StringPtr("testString"),
			// }

			quotaV1LogRulesModel := &logsv0.QuotaV1LogRules{
				Severities: []string{"debug"},
			}

			policyPrototypeModel := &logsv0.PolicyPrototypeQuotaV1CreatePolicyRequestSourceTypeRulesLogRules{
				Name:            core.StringPtr(nameForPayload),
				Description:     core.StringPtr("description updated"),
				Priority:        core.StringPtr("type_medium"),
				ApplicationRule: qoutaRuleModel,
				SubsystemRule:   qoutaRuleModel,
				// ArchiveRetention: quotaV1ArchiveRetentionModel,
				LogRules: quotaV1LogRulesModel,
			}

			createPolicyOptions := &logsv0.CreatePolicyOptions{
				PolicyPrototype: policyPrototypeModel,
			}

			policy, response, err := logsService.CreatePolicy(createPolicyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(policy).ToNot(BeNil())

			p, ok := policy.(*logsv0.Policy)
			Expect(ok).To(BeTrue())
			policyID = p.ID
		})
	})

	Describe(`UpdatePolicy - Update Policy`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`UpdatePolicy(updatePolicyOptions *UpdatePolicyOptions)`, func() {
			qoutaRuleModel := &logsv0.QuotaV1Rule{
				RuleTypeID: core.StringPtr("is"),
				Name:       core.StringPtr("app"),
			}

			// quotaV1ArchiveRetentionModel := &logsv0.QuotaV1ArchiveRetention{
			// 	ID: core.StringPtr("testString"),
			// }

			quotaV1LogRulesModel := &logsv0.QuotaV1LogRules{
				Severities: []string{"debug"},
			}

			policyPrototypeModel := &logsv0.PolicyPrototypeQuotaV1CreatePolicyRequestSourceTypeRulesLogRules{
				Name:            core.StringPtr(nameForPayload),
				Description:     core.StringPtr("description"),
				Priority:        core.StringPtr("type_medium"),
				ApplicationRule: qoutaRuleModel,
				SubsystemRule:   qoutaRuleModel,
				// ArchiveRetention: quotaV1ArchiveRetentionModel,
				LogRules: quotaV1LogRulesModel,
			}

			updatePolicyOptions := &logsv0.UpdatePolicyOptions{
				ID:              policyID,
				PolicyPrototype: policyPrototypeModel,
			}

			policy, response, err := logsService.UpdatePolicy(updatePolicyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(policy).ToNot(BeNil())
		})
	})

	Describe(`GetCompanyPolicies - Get Company Policies`, func() {
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

	Describe(`GetPolicy - Get Policy`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetPolicy(getPolicyOptions *GetPolicyOptions)`, func() {
			getPolicyOptions := &logsv0.GetPolicyOptions{
				ID: policyID,
			}

			policy, response, err := logsService.GetPolicy(getPolicyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(policy).ToNot(BeNil())
		})
	})

	Describe(`DeletePolicy - Delete Policy`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeletePolicy(deletePolicyOptions *DeletePolicyOptions)`, func() {
			deletePolicyOptions := &logsv0.DeletePolicyOptions{
				ID: policyID,
			}

			response, err := logsService.DeletePolicy(deletePolicyOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`CreateDashboard - Create Dashboard`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateDashboard(createDashboardOptions *CreateDashboardOptions)`, func() {
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

			apisDashboardsV1CommonLogsAggregationCountModel := &logsv0.ApisDashboardsV1CommonLogsAggregationCount{}
			// apisDashboardsV1CommonLogsAggregationCountModel.SetProperty("foo", core.StringPtr("testString"))

			apisDashboardsV1CommonLogsAggregationModel := &logsv0.ApisDashboardsV1CommonLogsAggregationValueCount{
				Count: apisDashboardsV1CommonLogsAggregationCountModel,
			}

			apisDashboardsV1AstFilterEqualsSelectionAllSelectionModel := &logsv0.ApisDashboardsV1AstFilterEqualsSelectionAllSelection{}
			// apisDashboardsV1AstFilterEqualsSelectionAllSelectionModel.SetProperty("foo", core.StringPtr("testString"))

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
				// Interval:         core.StringPtr("1s"),
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
				// Href:        core.StringPtr("testString"),
				ID:          apisDashboardsV1UUIDModel,
				Title:       core.StringPtr("Response time"),
				Description: core.StringPtr("The average response time of the system"),
				Definition:  apisDashboardsV1AstWidgetDefinitionModel,
			}

			apisDashboardsV1AstRowModel := &logsv0.ApisDashboardsV1AstRow{
				// Href:       core.StringPtr("testString"),
				ID:         apisDashboardsV1UUIDModel,
				Appearance: apisDashboardsV1AstRowAppearanceModel,
				Widgets:    []logsv0.ApisDashboardsV1AstWidget{*apisDashboardsV1AstWidgetModel},
			}

			apisDashboardsV1AstSectionModel := &logsv0.ApisDashboardsV1AstSection{
				// Href: core.StringPtr("testString"),
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

			apisDashboardsV1AstMultiSelectSelectionAllSelectionModel := &logsv0.ApisDashboardsV1AstMultiSelectSelectionAllSelection{}
			// apisDashboardsV1AstMultiSelectSelectionAllSelectionModel.SetProperty("foo", core.StringPtr("testString"))

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

			apisDashboardsV1AstAnnotationMetricsSourceStartTimeMetricModel := &logsv0.ApisDashboardsV1AstAnnotationMetricsSourceStartTimeMetric{}
			// apisDashboardsV1AstAnnotationMetricsSourceStartTimeMetricModel.SetProperty("foo", core.StringPtr("testString"))

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
				// Href:    CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
				ID:      CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
				Name:    core.StringPtr("Deployments"),
				Enabled: core.BoolPtr(true),
				Source:  apisDashboardsV1AstAnnotationSourceModel,
			}

			apisDashboardsV1CommonTimeFrameModel := &logsv0.ApisDashboardsV1CommonTimeFrame{
				From: CreateMockDateTime("2019-01-01T12:00:00.000Z"),
				To:   CreateMockDateTime("2019-01-01T12:00:00.000Z"),
			}

			dashboardModel := &logsv0.DashboardApisDashboardsV1AstDashboardTimeFrameAbsoluteTimeFrame{
				// Href:              core.StringPtr("6U1Q8Hpa263Se8PkRKaiE"),
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
			dashboard, response, err := logsService.CreateDashboard(createDashboardOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(dashboard).ToNot(BeNil())

			dashboardID = *dashboard.(*logsv0.Dashboard).ID
			fmt.Println("DASHBOARD ID", dashboardID)
		})

	})

	Describe(`ReplaceDashboard - Replace Dashboard`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ReplaceDashboard(replaceDashboardOptions *ReplaceDashboardOptions)`, func() {
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

			apisDashboardsV1CommonLogsAggregationCountModel := &logsv0.ApisDashboardsV1CommonLogsAggregationCount{}
			// apisDashboardsV1CommonLogsAggregationCountModel.SetProperty("foo", core.StringPtr("testString"))

			apisDashboardsV1CommonLogsAggregationModel := &logsv0.ApisDashboardsV1CommonLogsAggregationValueCount{
				Count: apisDashboardsV1CommonLogsAggregationCountModel,
			}

			apisDashboardsV1AstFilterEqualsSelectionAllSelectionModel := &logsv0.ApisDashboardsV1AstFilterEqualsSelectionAllSelection{}
			// apisDashboardsV1AstFilterEqualsSelectionAllSelectionModel.SetProperty("foo", core.StringPtr("testString"))

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
				// Interval:         core.StringPtr("1s"),
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
				// Href:        core.StringPtr("testString"),
				ID:          apisDashboardsV1UUIDModel,
				Title:       core.StringPtr("Response time"),
				Description: core.StringPtr("The average response time of the system"),
				Definition:  apisDashboardsV1AstWidgetDefinitionModel,
			}

			apisDashboardsV1AstRowModel := &logsv0.ApisDashboardsV1AstRow{
				// Href:       core.StringPtr("testString"),
				ID:         apisDashboardsV1UUIDModel,
				Appearance: apisDashboardsV1AstRowAppearanceModel,
				Widgets:    []logsv0.ApisDashboardsV1AstWidget{*apisDashboardsV1AstWidgetModel},
			}

			apisDashboardsV1AstSectionModel := &logsv0.ApisDashboardsV1AstSection{
				// Href: core.StringPtr("testString"),
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

			apisDashboardsV1AstMultiSelectSelectionAllSelectionModel := &logsv0.ApisDashboardsV1AstMultiSelectSelectionAllSelection{}
			// apisDashboardsV1AstMultiSelectSelectionAllSelectionModel.SetProperty("foo", core.StringPtr("testString"))

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

			apisDashboardsV1AstAnnotationMetricsSourceStartTimeMetricModel := &logsv0.ApisDashboardsV1AstAnnotationMetricsSourceStartTimeMetric{}
			// apisDashboardsV1AstAnnotationMetricsSourceStartTimeMetricModel.SetProperty("foo", core.StringPtr("testString"))

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
				// Href:    CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
				ID:      CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
				Name:    core.StringPtr("Deployments"),
				Enabled: core.BoolPtr(true),
				Source:  apisDashboardsV1AstAnnotationSourceModel,
			}

			apisDashboardsV1CommonTimeFrameModel := &logsv0.ApisDashboardsV1CommonTimeFrame{
				From: CreateMockDateTime("2019-01-01T12:00:00.000Z"),
				To:   CreateMockDateTime("2019-01-01T12:00:00.000Z"),
			}

			dashboardModel := &logsv0.DashboardApisDashboardsV1AstDashboardTimeFrameAbsoluteTimeFrame{
				// Href:              core.StringPtr("6U1Q8Hpa263Se8PkRKaiE"),
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
				Dashboard:   dashboardModel,
			}

			dashboard, response, err := logsService.ReplaceDashboard(replaceDashboardOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(dashboard).ToNot(BeNil())
		})
	})

	Describe(`GetDashboard - Get Dashboard`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetDashboard(getDashboardOptions *GetDashboardOptions)`, func() {
			getDashboardOptions := &logsv0.GetDashboardOptions{
				DashboardID: core.StringPtr(dashboardID),
			}

			dashboard, response, err := logsService.GetDashboard(getDashboardOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(dashboard).ToNot(BeNil())
		})
	})

	Describe(`DeleteDashboard - Delete Dashboard`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteDashboard(deleteDashboardOptions *DeleteDashboardOptions)`, func() {
			deleteDashboardOptions := &logsv0.DeleteDashboardOptions{
				DashboardID: core.StringPtr(dashboardID),
			}

			response, err := logsService.DeleteDashboard(deleteDashboardOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`CreateE2m - Create E2m`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CreateE2m(createE2mOptions *CreateE2mOptions)`, func() {
			// apisEvents2metricsV2MetricLabelModel := &logsv0.ApisEvents2metricsV2MetricLabel{
			// 	TargetLabel: core.StringPtr("testString"),
			// 	SourceField: core.StringPtr("testString"),
			// }

			// apisEvents2metricsV2E2mAggSamplesModel := &logsv0.ApisEvents2metricsV2E2mAggSamples{
			// 	SampleType: core.StringPtr("unspecified"),
			// }

			// apisEvents2metricsV2AggregationModel := &logsv0.ApisEvents2metricsV2AggregationAggMetadataSamples{
			// 	Enabled:          core.BoolPtr(true),
			// 	AggType:          core.StringPtr("unspecified"),
			// 	TargetMetricName: core.StringPtr("testString"),
			// 	Samples:          apisEvents2metricsV2E2mAggSamplesModel,
			// }

			// apisEvents2metricsV2MetricFieldModel := &logsv0.ApisEvents2metricsV2MetricField{
			// 	TargetBaseMetricName: core.StringPtr("testString"),
			// 	SourceField:          core.StringPtr("testString"),
			// 	Aggregations:         []logsv0.ApisEvents2metricsV2AggregationIntf{apisEvents2metricsV2AggregationModel},
			// }

			apisLogs2metricsV2LogsQueryModel := &logsv0.ApisLogs2metricsV2LogsQuery{
				Lucene:                 core.StringPtr("testString"),
				Alias:                  core.StringPtr("testString"),
				ApplicationnameFilters: []string{"testString"},
				SubsystemnameFilters:   []string{"testString"},
				SeverityFilters:        []string{"unspecified"},
			}

			event2MetricPrototypeModel := &logsv0.Event2MetricPrototypeApisEvents2metricsV2E2mCreateParamsQueryLogsQuery{
				Name:              core.StringPtr(nameForPayload),
				Description:       core.StringPtr("Test"),
				PermutationsLimit: core.Int64Ptr(int64(1)),
				// MetricLabels:      []logsv0.ApisEvents2metricsV2MetricLabel{*apisEvents2metricsV2MetricLabelModel},
				// MetricFields:      []logsv0.ApisEvents2metricsV2MetricField{*apisEvents2metricsV2MetricFieldModel},
				Type:      core.StringPtr("logs2metrics"),
				LogsQuery: apisLogs2metricsV2LogsQueryModel,
			}

			createE2mOptions := &logsv0.CreateE2mOptions{
				Event2MetricPrototype: event2MetricPrototypeModel,
			}

			event2Metric, response, err := logsService.CreateE2m(createE2mOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(event2Metric).ToNot(BeNil())

			e2m, ok := event2Metric.(*logsv0.Event2Metric)
			Expect(ok).To(Equal(true))
			event2MetricsID = e2m.ID
		})
	})

	Describe(`ReplaceE2m - Replace E2m`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`ReplaceE2m(replaceE2mOptions *ReplaceE2mOptions)`, func() {
			// apisEvents2metricsV2MetricLabelModel := &logsv0.ApisEvents2metricsV2MetricLabel{
			// 	TargetLabel: core.StringPtr("testString"),
			// 	SourceField: core.StringPtr("testString"),
			// }

			// apisEvents2metricsV2E2mAggSamplesModel := &logsv0.ApisEvents2metricsV2E2mAggSamples{
			// 	SampleType: core.StringPtr("unspecified"),
			// }

			// apisEvents2metricsV2AggregationModel := &logsv0.ApisEvents2metricsV2AggregationAggMetadataSamples{
			// 	Enabled:          core.BoolPtr(true),
			// 	AggType:          core.StringPtr("unspecified"),
			// 	TargetMetricName: core.StringPtr("testString"),
			// 	Samples:          apisEvents2metricsV2E2mAggSamplesModel,
			// }

			// apisEvents2metricsV2MetricFieldModel := &logsv0.ApisEvents2metricsV2MetricField{
			// 	TargetBaseMetricName: core.StringPtr("testString"),
			// 	SourceField:          core.StringPtr("testString"),
			// 	Aggregations:         []logsv0.ApisEvents2metricsV2AggregationIntf{apisEvents2metricsV2AggregationModel},
			// }

			apisLogs2metricsV2LogsQueryModel := &logsv0.ApisLogs2metricsV2LogsQuery{
				Lucene:                 core.StringPtr("testString"),
				Alias:                  core.StringPtr("testString"),
				ApplicationnameFilters: []string{"testString"},
				SubsystemnameFilters:   []string{"testString"},
				SeverityFilters:        []string{"unspecified"},
			}

			event2MetricPrototypeModel := &logsv0.Event2MetricPrototypeApisEvents2metricsV2E2mCreateParamsQueryLogsQuery{
				Name:              core.StringPtr(nameForPayload),
				Description:       core.StringPtr("Test update"),
				PermutationsLimit: core.Int64Ptr(int64(1)),
				// MetricLabels:      []logsv0.ApisEvents2metricsV2MetricLabel{*apisEvents2metricsV2MetricLabelModel},
				// MetricFields:      []logsv0.ApisEvents2metricsV2MetricField{*apisEvents2metricsV2MetricFieldModel},
				Type:      core.StringPtr("logs2metrics"),
				LogsQuery: apisLogs2metricsV2LogsQueryModel,
			}

			replaceE2mOptions := &logsv0.ReplaceE2mOptions{
				ID:                    core.StringPtr(event2MetricsID.String()),
				Event2MetricPrototype: event2MetricPrototypeModel,
			}

			event2Metric, response, err := logsService.ReplaceE2m(replaceE2mOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(event2Metric).ToNot(BeNil())
		})
	})

	Describe(`ListE2m - List E2m`, func() {
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

	Describe(`GetE2m - Get E2m`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetE2m(getE2mOptions *GetE2mOptions)`, func() {
			getE2mOptions := &logsv0.GetE2mOptions{
				ID: core.StringPtr(event2MetricsID.String()),
			}

			event2Metric, response, err := logsService.GetE2m(getE2mOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(event2Metric).ToNot(BeNil())
		})
	})

	Describe(`DeleteE2m - Delete E2m`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteE2m(deleteE2mOptions *DeleteE2mOptions)`, func() {
			deleteE2mOptions := &logsv0.DeleteE2mOptions{
				ID: core.StringPtr(event2MetricsID.String()),
			}

			response, err := logsService.DeleteE2m(deleteE2mOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`CreateViewFolder - Create View Folder`, func() {
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

			viewFolderID = viewFolder.ID
		})
	})

	Describe(`GetViewFolder - Get View Folder`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetViewFolder(getViewFolderOptions *GetViewFolderOptions)`, func() {
			getViewFolderOptions := &logsv0.GetViewFolderOptions{
				ID: viewFolderID,
			}

			viewFolder, response, err := logsService.GetViewFolder(getViewFolderOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(viewFolder).ToNot(BeNil())
		})
	})

	// Describe(`ReplaceViewFolder - Replace View Folder`, func() {
	// 	BeforeEach(func() {
	// 		shouldSkipTest()
	// 	})
	// 	It(`ReplaceViewFolder(replaceViewFolderOptions *ReplaceViewFolderOptions)`, func() {
	// 		replaceViewFolderOptions := &logsv0.ReplaceViewFolderOptions{
	// 			ID:   viewFolderID,
	// 			Name: core.StringPtr("My Folder"),
	// 		}

	// 		viewFolder, response, err := logsService.ReplaceViewFolder(replaceViewFolderOptions)
	// 		Expect(err).To(BeNil())
	// 		Expect(response.StatusCode).To(Equal(200))
	// 		Expect(viewFolder).ToNot(BeNil())
	// 	})
	// })

	Describe(`CreateView - Create View`, func() {
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
				FolderID:      viewFolderID,
			}

			view, response, err := logsService.CreateView(createViewOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(view).ToNot(BeNil())

			viewID = *view.ID
		})
	})

	Describe(`GetView - Get View`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetView(getViewOptions *GetViewOptions)`, func() {
			getViewOptions := &logsv0.GetViewOptions{
				ID: core.Int64Ptr(viewID),
			}

			view, response, err := logsService.GetView(getViewOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(view).ToNot(BeNil())
		})
	})

	Describe(`ReplaceView - Replace View`, func() {
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
				ID:            core.Int64Ptr(viewID),
				Name:          core.StringPtr("Logs view"),
				SearchQuery:   apisViewsV1SearchQueryModel,
				TimeSelection: apisViewsV1TimeSelectionModel,
				Filters:       apisViewsV1SelectedFiltersModel,
				FolderID:      viewFolderID,
			}

			view, response, err := logsService.ReplaceView(replaceViewOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(view).ToNot(BeNil())
		})
	})

	Describe(`DeleteView - Delete View`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteView(deleteViewOptions *DeleteViewOptions)`, func() {
			deleteViewOptions := &logsv0.DeleteViewOptions{
				ID: core.Int64Ptr(viewID),
			}

			response, err := logsService.DeleteView(deleteViewOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})

	Describe(`ListViewFolders - List View Folders`, func() {
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

	Describe(`DeleteViewFolder - Delete View Folder`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`DeleteViewFolder(deleteViewFolderOptions *DeleteViewFolderOptions)`, func() {
			deleteViewFolderOptions := &logsv0.DeleteViewFolderOptions{
				ID: viewFolderID,
			}

			response, err := logsService.DeleteViewFolder(deleteViewFolderOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})
})
