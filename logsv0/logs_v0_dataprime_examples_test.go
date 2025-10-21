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
	"context"
	"fmt"
	"os"
	"sync"

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

	const externalConfigFile = "../logs_v0.env"

	var (
		logsService *logsv0.LogsV0
		config      map[string]string
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
		It(`Query request example`, func() {
			fmt.Println("\nQuery() result:")
			// begin-query
			query := "source logs | limit 10"
			queryOptions := logsv0.QueryOptions{
				Query: &query,
				Metadata: &logsv0.ApisDataprimeV1Metadata{
					StartDate: CreateDateTime("2024-03-01T20:47:12.940Z"),
					EndDate:   CreateDateTime("2024-03-06T20:47:12.940Z"),
					Tier:      core.StringPtr("frequent_search"),
					Syntax:    core.StringPtr("dataprime"),
				},
			}
			var (
				wg sync.WaitGroup
			)

			// Define custom callback to collect results and errors

			wg.Add(1)
			go func() {
				defer wg.Done()
				logsService.QueryWithContext(context.Background(), &queryOptions, callBack{})
			}()

			wg.Wait()

			// end-query

		})
	})
})

func CreateDateTime(mockData string) *strfmt.DateTime {
	d, err := core.ParseDateTime(mockData)
	if err != nil {
		return nil
	}
	return &d
}
