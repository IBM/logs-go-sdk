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

var _ = Describe(`LogsV1 Integration Tests`, func() {
	const externalConfigFile = "../logs.env"

	var (
		err         error
		logsService *logsv0.LogsV0
		serviceURL  string
		config      map[string]string
		bgqIdLink   strfmt.UUID
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

	Describe(`SubmitBackgroundQueryOptions - Submit background query`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`SubmitBackgroundQueryOptions(submitBackgroundQueryOptions *SubmitBackgroundQueryOptions) with warning`, func() {

			// Construct an instance of the submitBackgroundQueryOptions model
			submitBackgroundQueryOptions := &logsv0.SubmitBackgroundQueryOptions{
				StartDate: CreateMockDateTime("2024-03-08T00:00:00.00Z"),
				EndDate:   CreateMockDateTime("2024-03-08T23:59:00.00Z"),
				Query:     core.StringPtr("source logs | limit 20"),
				Syntax:    core.StringPtr("dataprime"),
			}
			bgq, response, err := logsService.SubmitBackgroundQuery(submitBackgroundQueryOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(202))
			Expect(bgq).ToNot(BeNil())
			bgqIdLink = *bgq.QueryID
			fmt.Fprintf(GinkgoWriter, "Saved bgqIdLink value: %v\n", bgqIdLink)

		})
	})

	Describe(`GetBackgroundQueryData - Get background query data`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetBackgroundQueryData(getBackgroundQueryDataOptions *GetBackgroundQueryDataOptions) with warning`, func() {

			// Construct an instance of the getBackgroundQueryDataOptions model
			getBackgroundQueryDataOptions := &logsv0.GetBackgroundQueryDataOptions{
				QueryID: &bgqIdLink,
			}
			logsService.GetBackgroundQueryData(getBackgroundQueryDataOptions, callBackIntegrationTest{})

		})
	})
	Describe(`GetBackgroundQueryStatus - Get background query status`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`GetBackgroundQueryStatus(getBackgroundQueryStatusOptions *GetBackgroundQueryStatusOptions) with warning`, func() {

			// Construct an instance of the getBackgroundQueryStatusOptions model
			getBackgroundQueryStatusOptions := &logsv0.GetBackgroundQueryStatusOptions{
				QueryID: &bgqIdLink,
			}
			bgq, response, err := logsService.GetBackgroundQueryStatus(getBackgroundQueryStatusOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(200))
			Expect(bgq).ToNot(BeNil())
		})
	})

	Describe(`CancelBackgroundQuery - Cancel background query`, func() {
		BeforeEach(func() {
			shouldSkipTest()
		})
		It(`CancelBackgroundQuery(cancelBackgroundQueryOptions *CancelBackgroundQueryOptions) with warning`, func() {

			// Construct an instance of the cancelBackgroundQueryOptions model
			cancelBackgroundQueryOptions := &logsv0.CancelBackgroundQueryOptions{
				QueryID: &bgqIdLink,
			}
			response, err := logsService.CancelBackgroundQuery(cancelBackgroundQueryOptions)
			Expect(err).To(BeNil())
			Expect(response.StatusCode).To(Equal(202))
		})
	})

})
