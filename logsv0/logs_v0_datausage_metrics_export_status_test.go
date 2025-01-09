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
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/IBM/logs-go-sdk/logsv0"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe(`LogsV0`, func() {
	var testServer *httptest.Server

	Describe(`GetDataUsageMetricsExportStatus(getDataUsageMetricsExportStatusOptions *GetDataUsageMetricsExportStatusOptions) - Operation response error`, func() {
		getDataUsageMetricsExportStatusPath := "/v1/data_usage"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getDataUsageMetricsExportStatusPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke GetDataUsageMetricsExportStatus with error: Operation response processing error`, func() {
				logsService, serviceErr := logsv0.NewLogsV0(&logsv0.LogsV0Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(logsService).ToNot(BeNil())

				// Construct an instance of the GetDataUsageMetricsExportStatusOptions model
				getDataUsageMetricsExportStatusOptionsModel := new(logsv0.GetDataUsageMetricsExportStatusOptions)
				getDataUsageMetricsExportStatusOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				result, response, operationErr := logsService.GetDataUsageMetricsExportStatus(getDataUsageMetricsExportStatusOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())

				// Enable retries and test again
				logsService.EnableRetries(0, 0)
				result, response, operationErr = logsService.GetDataUsageMetricsExportStatus(getDataUsageMetricsExportStatusOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})

	Describe(`GetDataUsageMetricsExportStatus(getDataUsageMetricsExportStatusOptions *GetDataUsageMetricsExportStatusOptions)`, func() {
		getDataUsageMetricsExportStatusPath := "/v1/data_usage"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getDataUsageMetricsExportStatusPath))
					Expect(req.Method).To(Equal("GET"))

					// Sleep a short time to support a timeout test
					time.Sleep(100 * time.Millisecond)

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"enabled": true}`)
				}))
			})
			It(`Invoke GetDataUsageMetricsExportStatus successfully with retries`, func() {
				logsService, serviceErr := logsv0.NewLogsV0(&logsv0.LogsV0Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(logsService).ToNot(BeNil())
				logsService.EnableRetries(0, 0)

				// Construct an instance of the GetDataUsageMetricsExportStatusOptions model
				getDataUsageMetricsExportStatusOptionsModel := new(logsv0.GetDataUsageMetricsExportStatusOptions)
				getDataUsageMetricsExportStatusOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				_, _, operationErr := logsService.GetDataUsageMetricsExportStatusWithContext(ctx, getDataUsageMetricsExportStatusOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))

				// Disable retries and test again
				logsService.DisableRetries()
				result, response, operationErr := logsService.GetDataUsageMetricsExportStatus(getDataUsageMetricsExportStatusOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

				// Re-test the timeout error with retries disabled
				ctx, cancelFunc2 := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc2()
				_, _, operationErr = logsService.GetDataUsageMetricsExportStatusWithContext(ctx, getDataUsageMetricsExportStatusOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring("deadline exceeded"))
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(getDataUsageMetricsExportStatusPath))
					Expect(req.Method).To(Equal("GET"))

					// Set mock response
					res.Header().Set("Content-type", "application/json")
					res.WriteHeader(200)
					fmt.Fprintf(res, "%s", `{"enabled": true}`)
				}))
			})
			It(`Invoke GetDataUsageMetricsExportStatus successfully`, func() {
				logsService, serviceErr := logsv0.NewLogsV0(&logsv0.LogsV0Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(logsService).ToNot(BeNil())

				// Invoke operation with nil options model (negative test)
				result, response, operationErr := logsService.GetDataUsageMetricsExportStatus(nil)
				Expect(operationErr).NotTo(BeNil())
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())

				// Construct an instance of the GetDataUsageMetricsExportStatusOptions model
				getDataUsageMetricsExportStatusOptionsModel := new(logsv0.GetDataUsageMetricsExportStatusOptions)
				getDataUsageMetricsExportStatusOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				result, response, operationErr = logsService.GetDataUsageMetricsExportStatus(getDataUsageMetricsExportStatusOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())
				Expect(result).ToNot(BeNil())

			})
			It(`Invoke GetDataUsageMetricsExportStatus with error: Operation request error`, func() {
				logsService, serviceErr := logsv0.NewLogsV0(&logsv0.LogsV0Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(logsService).ToNot(BeNil())

				// Construct an instance of the GetDataUsageMetricsExportStatusOptions model
				getDataUsageMetricsExportStatusOptionsModel := new(logsv0.GetDataUsageMetricsExportStatusOptions)
				getDataUsageMetricsExportStatusOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := logsService.SetServiceURL("")
				Expect(err).To(BeNil())
				result, response, operationErr := logsService.GetDataUsageMetricsExportStatus(getDataUsageMetricsExportStatusOptionsModel)
				Expect(operationErr).ToNot(BeNil())
				Expect(operationErr.Error()).To(ContainSubstring(core.ERRORMSG_SERVICE_URL_MISSING))
				Expect(response).To(BeNil())
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with missing response body`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Set success status code with no respoonse body
					res.WriteHeader(200)
				}))
			})
			It(`Invoke GetDataUsageMetricsExportStatus successfully`, func() {
				logsService, serviceErr := logsv0.NewLogsV0(&logsv0.LogsV0Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(logsService).ToNot(BeNil())

				// Construct an instance of the GetDataUsageMetricsExportStatusOptions model
				getDataUsageMetricsExportStatusOptionsModel := new(logsv0.GetDataUsageMetricsExportStatusOptions)
				getDataUsageMetricsExportStatusOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				result, response, operationErr := logsService.GetDataUsageMetricsExportStatus(getDataUsageMetricsExportStatusOptionsModel)
				Expect(operationErr).To(BeNil())
				Expect(response).ToNot(BeNil())

				// Verify a nil result
				Expect(result).To(BeNil())
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})

})
