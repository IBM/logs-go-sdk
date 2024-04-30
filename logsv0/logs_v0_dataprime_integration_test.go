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

var (
	expectedLabels = []logsv0.ApisDataprimeV1DataprimeResultsKeyValue{
		{
			Key:   core.StringPtr("applicationname"),
			Value: core.StringPtr("app-name"),
		},
		{
			Key:   core.StringPtr("subsystemname"),
			Value: core.StringPtr("app-sub"),
		},
		{
			Key: core.StringPtr("threadid"),
		},
		{
			Key: core.StringPtr("ipaddress"),
		},
		{
			Key: core.StringPtr("computername"),
		},
	}
	expectedUserData = "{\"text\":\"Push and Query integration test\"}"
	expectedWarning  = "Start date must be before end date"
)

var _ = Describe(`LogsV1 Integration Tests`, func() {
	const externalConfigFile = "../logs.env"

	var (
		err         error
		logsService *logsv0.LogsV0
		serviceURL  string
		config      map[string]string
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
			fmt.Fprintf(GinkgoWriter, "skip test passed")
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

	Describe(`Query - Query`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`Query(queryOptions *QueryOptions) with warning`, func() {
			apisDataprimeV1MetadataModel := &logsv0.ApisDataprimeV1Metadata{
				StartDate: CreateMockDateTime("2024-03-08T00:00:00.00Z"),
				EndDate:   CreateMockDateTime("2024-03-07T23:59:00.00Z"),
				Tier:      core.StringPtr("frequent_search"),
				Syntax:    core.StringPtr("dataprime"),
			}

			queryOptions := &logsv0.QueryOptions{
				Query:    core.StringPtr("source logs | limit 10"),
				Metadata: apisDataprimeV1MetadataModel,
			}

			logsService.Query(queryOptions, callBackIntegrationTest{})
		})
		It(`Query(queryOptions *QueryOptions) with result`, func() {
			apisDataprimeV1MetadataModel := &logsv0.ApisDataprimeV1Metadata{
				StartDate: CreateMockDateTime("2024-03-08T00:00:00.00Z"),
				EndDate:   CreateMockDateTime("2024-03-08T23:59:00.00Z"),
				Tier:      core.StringPtr("frequent_search"),
				Syntax:    core.StringPtr("dataprime"),
			}

			queryOptions := &logsv0.QueryOptions{
				Query:    core.StringPtr("source logs | limit 10"),
				Metadata: apisDataprimeV1MetadataModel,
			}

			logsService.Query(queryOptions, callBackIntegrationTest{})
		})
	})

})

type callBackIntegrationTest struct{}

func (cb callBackIntegrationTest) OnClose() {
}

func (cb callBackIntegrationTest) OnError(err error) {
}

func (cb callBackIntegrationTest) OnData(detailedResponse *core.DetailedResponse) {
	Expect(detailedResponse.Result).ToNot(BeNil())
	queryResponse := detailedResponse.Result.(*logsv0.QueryResponseStreamItem)
	if queryResponse.QueryID != nil {
		return
	}
	if queryResponse.Warning != nil {
		warningMessage := queryResponse.Warning.(*logsv0.ApisDataprimeV1DataprimeWarning).TimeRangeWarning.WarningMessage
		Expect(*warningMessage).To(ContainSubstring(expectedWarning))
		return
	}

	Expect(queryResponse.Result).ToNot(BeNil())
	Expect(len(queryResponse.Result.Results)).To(Equal(1))
	data := queryResponse.Result.Results[0]
	Expect(data.Labels).To(Equal(expectedLabels))
	Expect(*data.UserData).To(Equal(expectedUserData))
}
