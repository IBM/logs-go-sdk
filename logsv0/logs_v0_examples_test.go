//go:build examples

/**
 * (C) Copyright IBM Corp. 2025.
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

//
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
//
var _ = Describe(`LogsV0 Examples Tests`, func() {

	const externalConfigFile = "../logs_v0.env"

	var (
		logsService *logsv0.LogsV0
		config       map[string]string
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
		It(`GetAlert request example`, func() {
			fmt.Println("\nGetAlert() result:")
			// begin-get_alert

			getAlertOptions := logsService.NewGetAlertOptions(
				CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
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
				Threshold: core.Float64Ptr(float64(1)),
				Timeframe: core.StringPtr("timeframe_10_min"),
				GroupBy: []string{"coralogix.metadata.applicationName"},
				IgnoreInfinity: core.BoolPtr(true),
				RelativeTimeframe: core.StringPtr("hour_or_unspecified"),
				CardinalityFields: []string{},
			}

			alertsV2MoreThanConditionModel := &logsv0.AlertsV2MoreThanCondition{
				Parameters: alertsV2ConditionParametersModel,
				EvaluationWindow: core.StringPtr("rolling_or_unspecified"),
			}

			alertsV2AlertConditionModel := &logsv0.AlertsV2AlertConditionConditionMoreThan{
				MoreThan: alertsV2MoreThanConditionModel,
			}

			alertsV2AlertNotificationModel := &logsv0.AlertsV2AlertNotificationIntegrationTypeIntegrationID{
			}

			alertsV2AlertNotificationGroupsModel := &logsv0.AlertsV2AlertNotificationGroups{
				GroupByFields: []string{"coralogix.metadata.applicationName"},
				Notifications: []logsv0.AlertsV2AlertNotificationIntf{alertsV2AlertNotificationModel},
			}

			alertsV1AlertFiltersMetadataFiltersModel := &logsv0.AlertsV1AlertFiltersMetadataFilters{
			}

			alertsV1AlertFiltersRatioAlertModel := &logsv0.AlertsV1AlertFiltersRatioAlert{
				Alias: core.StringPtr("TopLevelAlert"),
			}

			alertsV1AlertFiltersModel := &logsv0.AlertsV1AlertFilters{
				Severities: []string{"info"},
				Metadata: alertsV1AlertFiltersMetadataFiltersModel,
				Text: core.StringPtr("initiator.id.keyword:iam-ServiceId-10820fd6-c3fe-414e-8fd5-44ce95f7d34d AND action.keyword:cloud-object-storage.object.create"),
				RatioAlerts: []logsv0.AlertsV1AlertFiltersRatioAlert{*alertsV1AlertFiltersRatioAlertModel},
				FilterType: core.StringPtr("text_or_unspecified"),
			}

			alertsV1TimeModel := &logsv0.AlertsV1Time{
				Hours: core.Int64Ptr(int64(18)),
				Minutes: core.Int64Ptr(int64(30)),
				Seconds: core.Int64Ptr(int64(0)),
			}

			alertsV1TimeRangeModel := &logsv0.AlertsV1TimeRange{
				Start: alertsV1TimeModel,
				End: alertsV1TimeModel,
			}

			alertsV1AlertActiveTimeframeModel := &logsv0.AlertsV1AlertActiveTimeframe{
				DaysOfWeek: []string{"sunday", "monday_or_unspecified", "tuesday", "wednesday", "thursday", "friday", "saturday"},
				Range: alertsV1TimeRangeModel,
			}

			alertsV1AlertActiveWhenModel := &logsv0.AlertsV1AlertActiveWhen{
				Timeframes: []logsv0.AlertsV1AlertActiveTimeframe{*alertsV1AlertActiveTimeframeModel},
			}

			alertsV1MetaLabelModel := &logsv0.AlertsV1MetaLabel{
				Key: core.StringPtr("env"),
				Value: core.StringPtr("dev"),
			}

			alertsV2AlertIncidentSettingsModel := &logsv0.AlertsV2AlertIncidentSettings{
				RetriggeringPeriodSeconds: core.Int64Ptr(int64(300)),
				NotifyOn: core.StringPtr("triggered_only"),
				UseAsNotificationSettings: core.BoolPtr(true),
			}

			updateAlertOptions := logsService.NewUpdateAlertOptions(
				CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
				"Test alert",
				true,
				"info_or_unspecified",
				alertsV2AlertConditionModel,
			)
			updateAlertOptions.SetDescription("Alert if the number of logs reaches a threshold")
			updateAlertOptions.SetNotificationGroups([]logsv0.AlertsV2AlertNotificationGroups{*alertsV2AlertNotificationGroupsModel})
			updateAlertOptions.SetFilters(alertsV1AlertFiltersModel)
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
		It(`CreateAlert request example`, func() {
			fmt.Println("\nCreateAlert() result:")
			// begin-create_alert

			alertsV2ConditionParametersModel := &logsv0.AlertsV2ConditionParameters{
				Threshold: core.Float64Ptr(float64(1)),
				Timeframe: core.StringPtr("timeframe_10_min"),
				GroupBy: []string{"coralogix.metadata.applicationName"},
				IgnoreInfinity: core.BoolPtr(true),
				RelativeTimeframe: core.StringPtr("hour_or_unspecified"),
				CardinalityFields: []string{},
			}

			alertsV2MoreThanConditionModel := &logsv0.AlertsV2MoreThanCondition{
				Parameters: alertsV2ConditionParametersModel,
				EvaluationWindow: core.StringPtr("rolling_or_unspecified"),
			}

			alertsV2AlertConditionModel := &logsv0.AlertsV2AlertConditionConditionMoreThan{
				MoreThan: alertsV2MoreThanConditionModel,
			}

			alertsV2AlertNotificationModel := &logsv0.AlertsV2AlertNotificationIntegrationTypeIntegrationID{
			}

			alertsV2AlertNotificationGroupsModel := &logsv0.AlertsV2AlertNotificationGroups{
				GroupByFields: []string{"coralogix.metadata.applicationName"},
				Notifications: []logsv0.AlertsV2AlertNotificationIntf{alertsV2AlertNotificationModel},
			}

			alertsV1AlertFiltersMetadataFiltersModel := &logsv0.AlertsV1AlertFiltersMetadataFilters{
			}

			alertsV1AlertFiltersRatioAlertModel := &logsv0.AlertsV1AlertFiltersRatioAlert{
				Alias: core.StringPtr("TopLevelAlert"),
			}

			alertsV1AlertFiltersModel := &logsv0.AlertsV1AlertFilters{
				Severities: []string{"info"},
				Metadata: alertsV1AlertFiltersMetadataFiltersModel,
				Text: core.StringPtr("initiator.id.keyword:iam-ServiceId-10820fd6-c3fe-414e-8fd5-44ce95f7d34d AND action.keyword:cloud-object-storage.object.create"),
				RatioAlerts: []logsv0.AlertsV1AlertFiltersRatioAlert{*alertsV1AlertFiltersRatioAlertModel},
				FilterType: core.StringPtr("text_or_unspecified"),
			}

			alertsV1TimeModel := &logsv0.AlertsV1Time{
				Hours: core.Int64Ptr(int64(18)),
				Minutes: core.Int64Ptr(int64(30)),
				Seconds: core.Int64Ptr(int64(0)),
			}

			alertsV1TimeRangeModel := &logsv0.AlertsV1TimeRange{
				Start: alertsV1TimeModel,
				End: alertsV1TimeModel,
			}

			alertsV1AlertActiveTimeframeModel := &logsv0.AlertsV1AlertActiveTimeframe{
				DaysOfWeek: []string{"sunday", "monday_or_unspecified", "tuesday", "wednesday", "thursday", "friday", "saturday"},
				Range: alertsV1TimeRangeModel,
			}

			alertsV1AlertActiveWhenModel := &logsv0.AlertsV1AlertActiveWhen{
				Timeframes: []logsv0.AlertsV1AlertActiveTimeframe{*alertsV1AlertActiveTimeframeModel},
			}

			alertsV1MetaLabelModel := &logsv0.AlertsV1MetaLabel{
				Key: core.StringPtr("env"),
				Value: core.StringPtr("dev"),
			}

			alertsV2AlertIncidentSettingsModel := &logsv0.AlertsV2AlertIncidentSettings{
				RetriggeringPeriodSeconds: core.Int64Ptr(int64(300)),
				NotifyOn: core.StringPtr("triggered_only"),
				UseAsNotificationSettings: core.BoolPtr(true),
			}

			createAlertOptions := logsService.NewCreateAlertOptions(
				"Test alert",
				true,
				"info_or_unspecified",
				alertsV2AlertConditionModel,
			)
			createAlertOptions.SetDescription("Alert if the number of logs reaches a threshold")
			createAlertOptions.SetNotificationGroups([]logsv0.AlertsV2AlertNotificationGroups{*alertsV2AlertNotificationGroupsModel})
			createAlertOptions.SetFilters(alertsV1AlertFiltersModel)
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
		})
		It(`GetRuleGroup request example`, func() {
			fmt.Println("\nGetRuleGroup() result:")
			// begin-get_rule_group

			getRuleGroupOptions := logsService.NewGetRuleGroupOptions(
				CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
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
				Rule: core.StringPtr("(?P<timestamp>[^,]+),(?P<hostname>[^,]+),(?P<username>[^,]+),(?P<ip>[^,]+),(?P<connectionId>[0-9]+),(?P<queryId>[0-9]+),(?P<operation>[^,]+),(?P<database>[^,]+),'?(?P<object>.*)'?,(?P<returnCode>[0-9]+)"),
			}

			rulesV1RuleParametersModel := &logsv0.RulesV1RuleParametersRuleParametersParseParameters{
				ParseParameters: rulesV1ParseParametersModel,
			}

			rulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRuleModel := &logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRule{
				Name: core.StringPtr("mysql-parse"),
				Description: core.StringPtr("mysql-parse"),
				SourceField: core.StringPtr("text"),
				Parameters: rulesV1RuleParametersModel,
				Enabled: core.BoolPtr(true),
				Order: core.Int64Ptr(int64(1)),
			}

			rulesV1CreateRuleGroupRequestCreateRuleSubgroupModel := &logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroup{
				Rules: []logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRule{*rulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRuleModel},
				Enabled: core.BoolPtr(true),
				Order: core.Int64Ptr(int64(1)),
			}

			rulesV1SubsystemNameConstraintModel := &logsv0.RulesV1SubsystemNameConstraint{
				Value: core.StringPtr("mysql"),
			}

			rulesV1RuleMatcherModel := &logsv0.RulesV1RuleMatcherConstraintSubsystemName{
				SubsystemName: rulesV1SubsystemNameConstraintModel,
			}

			updateRuleGroupOptions := logsService.NewUpdateRuleGroupOptions(
				CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
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
		It(`CreateRuleGroup request example`, func() {
			fmt.Println("\nCreateRuleGroup() result:")
			// begin-create_rule_group

			rulesV1ParseParametersModel := &logsv0.RulesV1ParseParameters{
				DestinationField: core.StringPtr("text"),
				Rule: core.StringPtr("(?P<timestamp>[^,]+),(?P<hostname>[^,]+),(?P<username>[^,]+),(?P<ip>[^,]+),(?P<connectionId>[0-9]+),(?P<queryId>[0-9]+),(?P<operation>[^,]+),(?P<database>[^,]+),'?(?P<object>.*)'?,(?P<returnCode>[0-9]+)"),
			}

			rulesV1RuleParametersModel := &logsv0.RulesV1RuleParametersRuleParametersParseParameters{
				ParseParameters: rulesV1ParseParametersModel,
			}

			rulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRuleModel := &logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRule{
				Name: core.StringPtr("mysql-parse"),
				Description: core.StringPtr("mysql-parse"),
				SourceField: core.StringPtr("text"),
				Parameters: rulesV1RuleParametersModel,
				Enabled: core.BoolPtr(true),
				Order: core.Int64Ptr(int64(1)),
			}

			rulesV1CreateRuleGroupRequestCreateRuleSubgroupModel := &logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroup{
				Rules: []logsv0.RulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRule{*rulesV1CreateRuleGroupRequestCreateRuleSubgroupCreateRuleModel},
				Enabled: core.BoolPtr(true),
				Order: core.Int64Ptr(int64(1)),
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
		It(`CreateOutgoingWebhook request example`, func() {
			fmt.Println("\nCreateOutgoingWebhook() result:")
			// begin-create_outgoing_webhook

			outgoingWebhookPrototypeModel := &logsv0.OutgoingWebhookPrototypeOutgoingWebhooksV1OutgoingWebhookInputDataConfigIbmEventNotifications{
				Type: core.StringPtr("ibm_event_notifications"),
				Name: core.StringPtr("Event Notifications Integration"),
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
		})
		It(`GetOutgoingWebhook request example`, func() {
			fmt.Println("\nGetOutgoingWebhook() result:")
			// begin-get_outgoing_webhook

			getOutgoingWebhookOptions := logsService.NewGetOutgoingWebhookOptions(
				CreateMockUUID("585bea36-bdd1-4bfb-9a26-51f1f8a12660"),
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

			outgoingWebhookPrototypeModel := &logsv0.OutgoingWebhookPrototypeOutgoingWebhooksV1OutgoingWebhookInputDataConfigIbmEventNotifications{
				Type: core.StringPtr("ibm_event_notifications"),
				Name: core.StringPtr("Event Notifications Integration"),
			}

			updateOutgoingWebhookOptions := logsService.NewUpdateOutgoingWebhookOptions(
				CreateMockUUID("585bea36-bdd1-4bfb-9a26-51f1f8a12660"),
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
				CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
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
				Name: core.StringPtr("policy-test"),
			}

			quotaV1LogRulesModel := &logsv0.QuotaV1LogRules{
				Severities: []string{"debug", "verbose", "info", "warning", "error"},
			}

			policyPrototypeModel := &logsv0.PolicyPrototypeQuotaV1CreatePolicyRequestSourceTypeRulesLogRules{
				Name: core.StringPtr("Med_policy"),
				Description: core.StringPtr("Medium policy"),
				Priority: core.StringPtr("type_high"),
				ApplicationRule: quotaV1RuleModel,
				SubsystemRule: quotaV1RuleModel,
				LogRules: quotaV1LogRulesModel,
			}

			updatePolicyOptions := logsService.NewUpdatePolicyOptions(
				CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
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
		It(`CreatePolicy request example`, func() {
			fmt.Println("\nCreatePolicy() result:")
			// begin-create_policy

			quotaV1RuleModel := &logsv0.QuotaV1Rule{
				RuleTypeID: core.StringPtr("is"),
				Name: core.StringPtr("policy-test"),
			}

			quotaV1LogRulesModel := &logsv0.QuotaV1LogRules{
				Severities: []string{"debug", "verbose", "info", "warning", "error"},
			}

			policyPrototypeModel := &logsv0.PolicyPrototypeQuotaV1CreatePolicyRequestSourceTypeRulesLogRules{
				Name: core.StringPtr("Med_policy"),
				Description: core.StringPtr("Medium Policy"),
				Priority: core.StringPtr("type_high"),
				ApplicationRule: quotaV1RuleModel,
				SubsystemRule: quotaV1RuleModel,
				LogRules: quotaV1LogRulesModel,
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
		})
		It(`GetDashboardCatalog request example`, func() {
			fmt.Println("\nGetDashboardCatalog() result:")
			// begin-get_dashboard_catalog

			getDashboardCatalogOptions := logsService.NewGetDashboardCatalogOptions()

			dashboardCollection, response, err := logsService.GetDashboardCatalog(getDashboardCatalogOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(dashboardCollection, "", "  ")
			fmt.Println(string(b))

			// end-get_dashboard_catalog

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(dashboardCollection).ToNot(BeNil())
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
				IsVisible: core.BoolPtr(true),
				GroupByQuery: core.BoolPtr(true),
			}

			apisDashboardsV1AstWidgetsLineChartTooltipModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartTooltip{
				ShowLabels: core.BoolPtr(false),
				Type: core.StringPtr("all"),
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
				ID: CreateMockUUID("e4560525-521c-49e7-a7de-a2925626c304"),
				Query: apisDashboardsV1AstWidgetsLineChartQueryModel,
				SeriesCountLimit: core.StringPtr("20"),
				ScaleType: core.StringPtr("linear"),
				Name: core.StringPtr("Query1"),
				IsVisible: core.BoolPtr(true),
				ColorScheme: core.StringPtr("classic"),
				Resolution: apisDashboardsV1AstWidgetsLineChartResolutionModel,
			}

			apisDashboardsV1AstWidgetsLineChartModel := &logsv0.ApisDashboardsV1AstWidgetsLineChart{
				Legend: apisDashboardsV1AstWidgetsCommonLegendModel,
				Tooltip: apisDashboardsV1AstWidgetsLineChartTooltipModel,
				QueryDefinitions: []logsv0.ApisDashboardsV1AstWidgetsLineChartQueryDefinition{*apisDashboardsV1AstWidgetsLineChartQueryDefinitionModel},
			}

			apisDashboardsV1AstWidgetDefinitionModel := &logsv0.ApisDashboardsV1AstWidgetDefinitionValueLineChart{
				LineChart: apisDashboardsV1AstWidgetsLineChartModel,
			}

			apisDashboardsV1AstWidgetModel := &logsv0.ApisDashboardsV1AstWidget{
				ID: apisDashboardsV1UUIDModel,
				Title: core.StringPtr("Size"),
				Definition: apisDashboardsV1AstWidgetDefinitionModel,
			}

			apisDashboardsV1AstRowModel := &logsv0.ApisDashboardsV1AstRow{
				ID: apisDashboardsV1UUIDModel,
				Appearance: apisDashboardsV1AstRowAppearanceModel,
				Widgets: []logsv0.ApisDashboardsV1AstWidget{*apisDashboardsV1AstWidgetModel},
			}

			apisDashboardsV1AstSectionModel := &logsv0.ApisDashboardsV1AstSection{
				ID: apisDashboardsV1UUIDModel,
				Rows: []logsv0.ApisDashboardsV1AstRow{*apisDashboardsV1AstRowModel},
			}

			apisDashboardsV1AstLayoutModel := &logsv0.ApisDashboardsV1AstLayout{
				Sections: []logsv0.ApisDashboardsV1AstSection{*apisDashboardsV1AstSectionModel},
			}

			apisDashboardsV1AstFilterEqualsSelectionListSelectionModel := &logsv0.ApisDashboardsV1AstFilterEqualsSelectionListSelection{
			}

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
				Scope: core.StringPtr("label"),
			}

			apisDashboardsV1AstFilterLogsFilterModel := &logsv0.ApisDashboardsV1AstFilterLogsFilter{
				Operator: apisDashboardsV1AstFilterOperatorModel,
				ObservationField: apisDashboardsV1CommonObservationFieldModel,
			}

			apisDashboardsV1AstFilterSourceModel := &logsv0.ApisDashboardsV1AstFilterSourceValueLogs{
				Logs: apisDashboardsV1AstFilterLogsFilterModel,
			}

			apisDashboardsV1AstFilterModel := &logsv0.ApisDashboardsV1AstFilter{
				Source: apisDashboardsV1AstFilterSourceModel,
				Enabled: core.BoolPtr(true),
				Collapsed: core.BoolPtr(false),
			}

			dashboardModel := &logsv0.DashboardApisDashboardsV1AstDashboardTimeFrameRelativeTimeFrame{
				Name: core.StringPtr("DataUsageToMetrics Dashboard"),
				Layout: apisDashboardsV1AstLayoutModel,
				Filters: []logsv0.ApisDashboardsV1AstFilter{*apisDashboardsV1AstFilterModel},
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
		})
		It(`GetDashboard request example`, func() {
			fmt.Println("\nGetDashboard() result:")
			// begin-get_dashboard

			getDashboardOptions := logsService.NewGetDashboardOptions(
				"testString",
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
				IsVisible: core.BoolPtr(true),
				GroupByQuery: core.BoolPtr(true),
			}

			apisDashboardsV1AstWidgetsLineChartTooltipModel := &logsv0.ApisDashboardsV1AstWidgetsLineChartTooltip{
				ShowLabels: core.BoolPtr(false),
				Type: core.StringPtr("all"),
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
				ID: CreateMockUUID("e4560525-521c-49e7-a7de-a2925626c304"),
				Query: apisDashboardsV1AstWidgetsLineChartQueryModel,
				SeriesCountLimit: core.StringPtr("20"),
				ScaleType: core.StringPtr("linear"),
				Name: core.StringPtr("Query1"),
				IsVisible: core.BoolPtr(true),
				ColorScheme: core.StringPtr("classic"),
				Resolution: apisDashboardsV1AstWidgetsLineChartResolutionModel,
			}

			apisDashboardsV1AstWidgetsLineChartModel := &logsv0.ApisDashboardsV1AstWidgetsLineChart{
				Legend: apisDashboardsV1AstWidgetsCommonLegendModel,
				Tooltip: apisDashboardsV1AstWidgetsLineChartTooltipModel,
				QueryDefinitions: []logsv0.ApisDashboardsV1AstWidgetsLineChartQueryDefinition{*apisDashboardsV1AstWidgetsLineChartQueryDefinitionModel},
			}

			apisDashboardsV1AstWidgetDefinitionModel := &logsv0.ApisDashboardsV1AstWidgetDefinitionValueLineChart{
				LineChart: apisDashboardsV1AstWidgetsLineChartModel,
			}

			apisDashboardsV1AstWidgetModel := &logsv0.ApisDashboardsV1AstWidget{
				ID: apisDashboardsV1UUIDModel,
				Title: core.StringPtr("Size"),
				Definition: apisDashboardsV1AstWidgetDefinitionModel,
			}

			apisDashboardsV1AstRowModel := &logsv0.ApisDashboardsV1AstRow{
				ID: apisDashboardsV1UUIDModel,
				Appearance: apisDashboardsV1AstRowAppearanceModel,
				Widgets: []logsv0.ApisDashboardsV1AstWidget{*apisDashboardsV1AstWidgetModel},
			}

			apisDashboardsV1AstSectionModel := &logsv0.ApisDashboardsV1AstSection{
				ID: apisDashboardsV1UUIDModel,
				Rows: []logsv0.ApisDashboardsV1AstRow{*apisDashboardsV1AstRowModel},
			}

			apisDashboardsV1AstLayoutModel := &logsv0.ApisDashboardsV1AstLayout{
				Sections: []logsv0.ApisDashboardsV1AstSection{*apisDashboardsV1AstSectionModel},
			}

			apisDashboardsV1AstFilterEqualsSelectionListSelectionModel := &logsv0.ApisDashboardsV1AstFilterEqualsSelectionListSelection{
			}

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
				Scope: core.StringPtr("label"),
			}

			apisDashboardsV1AstFilterLogsFilterModel := &logsv0.ApisDashboardsV1AstFilterLogsFilter{
				Operator: apisDashboardsV1AstFilterOperatorModel,
				ObservationField: apisDashboardsV1CommonObservationFieldModel,
			}

			apisDashboardsV1AstFilterSourceModel := &logsv0.ApisDashboardsV1AstFilterSourceValueLogs{
				Logs: apisDashboardsV1AstFilterLogsFilterModel,
			}

			apisDashboardsV1AstFilterModel := &logsv0.ApisDashboardsV1AstFilter{
				Source: apisDashboardsV1AstFilterSourceModel,
				Enabled: core.BoolPtr(true),
				Collapsed: core.BoolPtr(false),
			}

			dashboardModel := &logsv0.DashboardApisDashboardsV1AstDashboardTimeFrameRelativeTimeFrame{
				Name: core.StringPtr("DataUsageToMetrics Dashboard"),
				Layout: apisDashboardsV1AstLayoutModel,
				Filters: []logsv0.ApisDashboardsV1AstFilter{*apisDashboardsV1AstFilterModel},
				RelativeTimeFrame: core.StringPtr("86400s"),
			}

			replaceDashboardOptions := logsService.NewReplaceDashboardOptions(
				"testString",
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
			// begin-pin_dashboard

			pinDashboardOptions := logsService.NewPinDashboardOptions(
				"testString",
			)

			response, err := logsService.PinDashboard(pinDashboardOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from PinDashboard(): %d\n", response.StatusCode)
			}

			// end-pin_dashboard

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`ReplaceDefaultDashboard request example`, func() {
			// begin-replace_default_dashboard

			replaceDefaultDashboardOptions := logsService.NewReplaceDefaultDashboardOptions(
				"testString",
			)

			response, err := logsService.ReplaceDefaultDashboard(replaceDefaultDashboardOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from ReplaceDefaultDashboard(): %d\n", response.StatusCode)
			}

			// end-replace_default_dashboard

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`AssignDashboardFolder request example`, func() {
			// begin-assign_dashboard_folder

			assignDashboardFolderOptions := logsService.NewAssignDashboardFolderOptions(
				"testString",
				"testString",
			)

			response, err := logsService.AssignDashboardFolder(assignDashboardFolderOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from AssignDashboardFolder(): %d\n", response.StatusCode)
			}

			// end-assign_dashboard_folder

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
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
		})
		It(`GetDashboardFolder request example`, func() {
			fmt.Println("\nGetDashboardFolder() result:")
			// begin-get_dashboard_folder

			getDashboardFolderOptions := logsService.NewGetDashboardFolderOptions(
				CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
			)

			dashboardFolder, response, err := logsService.GetDashboardFolder(getDashboardFolderOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(dashboardFolder, "", "  ")
			fmt.Println(string(b))

			// end-get_dashboard_folder

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(dashboardFolder).ToNot(BeNil())
		})
		It(`ReplaceDashboardFolder request example`, func() {
			fmt.Println("\nReplaceDashboardFolder() result:")
			// begin-replace_dashboard_folder

			replaceDashboardFolderOptions := logsService.NewReplaceDashboardFolderOptions(
				CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
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
		It(`CreateE2m request example`, func() {
			fmt.Println("\nCreateE2m() result:")
			// begin-create_e2m

			apisLogs2metricsV2LogsQueryModel := &logsv0.ApisLogs2metricsV2LogsQuery{
				Lucene: core.StringPtr("logs"),
			}

			event2MetricPrototypeModel := &logsv0.Event2MetricPrototypeApisEvents2metricsV2E2mCreateParamsQueryLogsQuery{
				Name: core.StringPtr("test em2"),
				Description: core.StringPtr("Test e2m"),
				PermutationsLimit: core.Int64Ptr(int64(1)),
				Type: core.StringPtr("logs2metrics"),
				LogsQuery: apisLogs2metricsV2LogsQueryModel,
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
		})
		It(`GetE2m request example`, func() {
			fmt.Println("\nGetE2m() result:")
			// begin-get_e2m

			getE2mOptions := logsService.NewGetE2mOptions(
				"d6a3658e-78d2-47d0-9b81-b2c551f01b09",
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
				Name: core.StringPtr("test em2"),
				Description: core.StringPtr("Test e2m updated"),
				PermutationsLimit: core.Int64Ptr(int64(1)),
				Type: core.StringPtr("logs2metrics"),
				LogsQuery: apisLogs2metricsV2LogsQueryModel,
			}

			replaceE2mOptions := logsService.NewReplaceE2mOptions(
				"d6a3658e-78d2-47d0-9b81-b2c551f01b09",
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
		It(`CreateView request example`, func() {
			fmt.Println("\nCreateView() result:")
			// begin-create_view

			apisViewsV1CustomTimeSelectionModel := &logsv0.ApisViewsV1CustomTimeSelection{
				FromTime: CreateMockDateTime("2024-01-25T11:31:43.152Z"),
				ToTime: CreateMockDateTime("2024-01-25T11:37:13.238Z"),
			}

			apisViewsV1TimeSelectionModel := &logsv0.ApisViewsV1TimeSelectionSelectionTypeCustomSelection{
				CustomSelection: apisViewsV1CustomTimeSelectionModel,
			}

			apisViewsV1SearchQueryModel := &logsv0.ApisViewsV1SearchQuery{
				Query: core.StringPtr("logs"),
			}

			apisViewsV1FilterModel := &logsv0.ApisViewsV1Filter{
				Name: core.StringPtr("applicationName"),
				SelectedValues: map[string]bool{"key1": true},
			}

			apisViewsV1SelectedFiltersModel := &logsv0.ApisViewsV1SelectedFilters{
				Filters: []logsv0.ApisViewsV1Filter{*apisViewsV1FilterModel},
			}

			createViewOptions := logsService.NewCreateViewOptions(
				"Logs view",
				apisViewsV1TimeSelectionModel,
			)
			createViewOptions.SetSearchQuery(apisViewsV1SearchQueryModel)
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
		})
		It(`GetView request example`, func() {
			fmt.Println("\nGetView() result:")
			// begin-get_view

			getViewOptions := logsService.NewGetViewOptions(
				int64(52),
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

			apisViewsV1CustomTimeSelectionModel := &logsv0.ApisViewsV1CustomTimeSelection{
				FromTime: CreateMockDateTime("2024-01-25T11:31:43.152Z"),
				ToTime: CreateMockDateTime("2024-01-25T11:37:13.238Z"),
			}

			apisViewsV1TimeSelectionModel := &logsv0.ApisViewsV1TimeSelectionSelectionTypeCustomSelection{
				CustomSelection: apisViewsV1CustomTimeSelectionModel,
			}

			apisViewsV1SearchQueryModel := &logsv0.ApisViewsV1SearchQuery{
				Query: core.StringPtr("logs new"),
			}

			apisViewsV1FilterModel := &logsv0.ApisViewsV1Filter{
				Name: core.StringPtr("applicationName"),
				SelectedValues: map[string]bool{"key1": true},
			}

			apisViewsV1SelectedFiltersModel := &logsv0.ApisViewsV1SelectedFilters{
				Filters: []logsv0.ApisViewsV1Filter{*apisViewsV1FilterModel},
			}

			replaceViewOptions := logsService.NewReplaceViewOptions(
				int64(52),
				"Logs view",
				apisViewsV1TimeSelectionModel,
			)
			replaceViewOptions.SetSearchQuery(apisViewsV1SearchQueryModel)
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
		})
		It(`GetViewFolder request example`, func() {
			fmt.Println("\nGetViewFolder() result:")
			// begin-get_view_folder

			getViewFolderOptions := logsService.NewGetViewFolderOptions(
				CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
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
				CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
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
		It(`ListDataAccessRules request example`, func() {
			fmt.Println("\nListDataAccessRules() result:")
			// begin-list_data_access_rules

			listDataAccessRulesOptions := logsService.NewListDataAccessRulesOptions()
			listDataAccessRulesOptions.SetID([]strfmt.UUID{"4f966911-4bda-407e-b069-477394effa59"})

			dataAccessRuleCollection, response, err := logsService.ListDataAccessRules(listDataAccessRulesOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(dataAccessRuleCollection, "", "  ")
			fmt.Println(string(b))

			// end-list_data_access_rules

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(dataAccessRuleCollection).ToNot(BeNil())
		})
		It(`CreateDataAccessRule request example`, func() {
			fmt.Println("\nCreateDataAccessRule() result:")
			// begin-create_data_access_rule

			dataAccessRuleFilterModel := &logsv0.DataAccessRuleFilter{
				EntityType: core.StringPtr("logs"),
				Expression: core.StringPtr("<v1> foo == 'bar'"),
			}

			createDataAccessRuleOptions := logsService.NewCreateDataAccessRuleOptions(
				"Test Data Access Rule",
				[]logsv0.DataAccessRuleFilter{*dataAccessRuleFilterModel},
				"<v1> foo == 'bar'",
			)
			createDataAccessRuleOptions.SetDescription("Data Access Rule intended for testing")

			dataAccessRule, response, err := logsService.CreateDataAccessRule(createDataAccessRuleOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(dataAccessRule, "", "  ")
			fmt.Println(string(b))

			// end-create_data_access_rule

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(dataAccessRule).ToNot(BeNil())
		})
		It(`UpdateDataAccessRule request example`, func() {
			fmt.Println("\nUpdateDataAccessRule() result:")
			// begin-update_data_access_rule

			dataAccessRuleFilterModel := &logsv0.DataAccessRuleFilter{
				EntityType: core.StringPtr("logs"),
				Expression: core.StringPtr("<v1> foo == 'bar'"),
			}

			updateDataAccessRuleOptions := logsService.NewUpdateDataAccessRuleOptions(
				CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
				"Test Data Access Rule",
				[]logsv0.DataAccessRuleFilter{*dataAccessRuleFilterModel},
				"<v1> foo == 'bar'",
			)
			updateDataAccessRuleOptions.SetDescription("Data Access Rule intended for testing")

			dataAccessRule, response, err := logsService.UpdateDataAccessRule(updateDataAccessRuleOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(dataAccessRule, "", "  ")
			fmt.Println(string(b))

			// end-update_data_access_rule

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(dataAccessRule).ToNot(BeNil())
		})
		It(`GetEnrichments request example`, func() {
			fmt.Println("\nGetEnrichments() result:")
			// begin-get_enrichments

			getEnrichmentsOptions := logsService.NewGetEnrichmentsOptions()

			enrichmentCollection, response, err := logsService.GetEnrichments(getEnrichmentsOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(enrichmentCollection, "", "  ")
			fmt.Println(string(b))

			// end-get_enrichments

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(enrichmentCollection).ToNot(BeNil())
		})
		It(`CreateEnrichment request example`, func() {
			fmt.Println("\nCreateEnrichment() result:")
			// begin-create_enrichment

			enrichmentV1GeoIpTypeEmptyModel := &logsv0.EnrichmentV1GeoIpTypeEmpty{
			}

			enrichmentV1EnrichmentTypeModel := &logsv0.EnrichmentV1EnrichmentTypeTypeGeoIp{
				GeoIp: enrichmentV1GeoIpTypeEmptyModel,
			}

			createEnrichmentOptions := logsService.NewCreateEnrichmentOptions(
				"ip",
				enrichmentV1EnrichmentTypeModel,
			)

			enrichment, response, err := logsService.CreateEnrichment(createEnrichmentOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(enrichment, "", "  ")
			fmt.Println(string(b))

			// end-create_enrichment

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(enrichment).ToNot(BeNil())
		})
		It(`ExportDataUsage request example`, func() {
			fmt.Println("\nExportDataUsage() result:")
			// begin-export_data_usage

			exportDataUsageOptions := logsService.NewExportDataUsageOptions()
			exportDataUsageOptions.SetRange("last_week")
			exportDataUsageOptions.SetQuery("daily")

			exportDataUsageResponse, response, err := logsService.ExportDataUsage(exportDataUsageOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(exportDataUsageResponse, "", "  ")
			fmt.Println(string(b))

			// end-export_data_usage

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(exportDataUsageResponse).ToNot(BeNil())
		})
		It(`UpdateDataUsageMetricsExportStatus request example`, func() {
			fmt.Println("\nUpdateDataUsageMetricsExportStatus() result:")
			// begin-update_data_usage_metrics_export_status

			updateDataUsageMetricsExportStatusOptions := logsService.NewUpdateDataUsageMetricsExportStatusOptions(
				true,
			)

			dataUsageMetricsExportStatus, response, err := logsService.UpdateDataUsageMetricsExportStatus(updateDataUsageMetricsExportStatusOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(dataUsageMetricsExportStatus, "", "  ")
			fmt.Println(string(b))

			// end-update_data_usage_metrics_export_status

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(dataUsageMetricsExportStatus).ToNot(BeNil())
		})
		It(`GetEventStreamTargets request example`, func() {
			fmt.Println("\nGetEventStreamTargets() result:")
			// begin-get_event_stream_targets

			getEventStreamTargetsOptions := logsService.NewGetEventStreamTargetsOptions()

			streamCollection, response, err := logsService.GetEventStreamTargets(getEventStreamTargetsOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(streamCollection, "", "  ")
			fmt.Println(string(b))

			// end-get_event_stream_targets

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(streamCollection).ToNot(BeNil())
		})
		It(`CreateEventStreamTarget request example`, func() {
			fmt.Println("\nCreateEventStreamTarget() result:")
			// begin-create_event_stream_target

			ibmEventStreamsModel := &logsv0.IbmEventStreams{
				Brokers: core.StringPtr("kafka01.example.com:9093"),
				Topic: core.StringPtr("live.screen"),
			}

			createEventStreamTargetOptions := logsService.NewCreateEventStreamTargetOptions(
				"Live Screen",
				"<v1>contains(kubernetes.labels.CX_AZ, 'eu-west-1')",
			)
			createEventStreamTargetOptions.SetCompressionType("gzip")
			createEventStreamTargetOptions.SetIbmEventStreams(ibmEventStreamsModel)

			stream, response, err := logsService.CreateEventStreamTarget(createEventStreamTargetOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(stream, "", "  ")
			fmt.Println(string(b))

			// end-create_event_stream_target

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(201))
			Expect(stream).ToNot(BeNil())
		})
		It(`UpdateEventStreamTarget request example`, func() {
			fmt.Println("\nUpdateEventStreamTarget() result:")
			// begin-update_event_stream_target

			ibmEventStreamsModel := &logsv0.IbmEventStreams{
				Brokers: core.StringPtr("kafka01.example.com:9093"),
				Topic: core.StringPtr("live.screen"),
			}

			updateEventStreamTargetOptions := logsService.NewUpdateEventStreamTargetOptions(
				int64(0),
				"Live Screen",
				"<v1>contains(kubernetes.labels.CX_AZ, 'eu-west-1')",
			)
			updateEventStreamTargetOptions.SetCompressionType("gzip")
			updateEventStreamTargetOptions.SetIbmEventStreams(ibmEventStreamsModel)

			stream, response, err := logsService.UpdateEventStreamTarget(updateEventStreamTargetOptions)
			if err != nil {
				panic(err)
			}
			b, _ := json.MarshalIndent(stream, "", "  ")
			fmt.Println(string(b))

			// end-update_event_stream_target

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(stream).ToNot(BeNil())
		})
		It(`DeleteAlert request example`, func() {
			// begin-delete_alert

			deleteAlertOptions := logsService.NewDeleteAlertOptions(
				CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
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
				CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
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
				CreateMockUUID("585bea36-bdd1-4bfb-9a26-51f1f8a12660"),
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
				CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
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
		It(`DeleteDashboard request example`, func() {
			// begin-delete_dashboard

			deleteDashboardOptions := logsService.NewDeleteDashboardOptions(
				"testString",
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
		It(`UnpinDashboard request example`, func() {
			// begin-unpin_dashboard

			unpinDashboardOptions := logsService.NewUnpinDashboardOptions(
				"testString",
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
		It(`DeleteDashboardFolder request example`, func() {
			// begin-delete_dashboard_folder

			deleteDashboardFolderOptions := logsService.NewDeleteDashboardFolderOptions(
				CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
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
				"d6a3658e-78d2-47d0-9b81-b2c551f01b09",
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
				int64(52),
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
				CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
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
		It(`DeleteDataAccessRule request example`, func() {
			// begin-delete_data_access_rule

			deleteDataAccessRuleOptions := logsService.NewDeleteDataAccessRuleOptions(
				CreateMockUUID("3dc02998-0b50-4ea8-b68a-4779d716fa1f"),
			)

			response, err := logsService.DeleteDataAccessRule(deleteDataAccessRuleOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeleteDataAccessRule(): %d\n", response.StatusCode)
			}

			// end-delete_data_access_rule

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`RemoveEnrichments request example`, func() {
			// begin-remove_enrichments

			removeEnrichmentsOptions := logsService.NewRemoveEnrichmentsOptions(
				int64(1),
			)

			response, err := logsService.RemoveEnrichments(removeEnrichmentsOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from RemoveEnrichments(): %d\n", response.StatusCode)
			}

			// end-remove_enrichments

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
		It(`DeleteEventStreamTarget request example`, func() {
			// begin-delete_event_stream_target

			deleteEventStreamTargetOptions := logsService.NewDeleteEventStreamTargetOptions(
				int64(0),
			)

			response, err := logsService.DeleteEventStreamTarget(deleteEventStreamTargetOptions)
			if err != nil {
				panic(err)
			}
			if response.StatusCode != 204 {
				fmt.Printf("\nUnexpected response status code received from DeleteEventStreamTarget(): %d\n", response.StatusCode)
			}

			// end-delete_event_stream_target

			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(204))
		})
	})
})
