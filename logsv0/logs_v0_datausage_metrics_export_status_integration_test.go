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

var _ = Describe(`LogsV0 Integration Tests`, func() {
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
})
