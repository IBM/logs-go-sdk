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
	"bytes"
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

var (
	backgroundQueryEventTestData = "data: {\"response\": {{\"result\": {\"results\": []}}}\n\n"
)

var _ = Describe(`LogsV1`, func() {
	var testServer *httptest.Server
	Describe(`BackgroundQuery(queryOptions *SubmitBackgroundQueryOptions) - empty keep alive response`, func() {
		queryPath := "/v1/background_query/1234-567-890/data"
		Context(`empty keep alive response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(queryPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "text/event-stream")
					res.WriteHeader(200)
					fmt.Fprintf(res, ":\n\n")
				}))
			})
			It(`Invoke Query with empty keep alive response`, func() {
				logsService, serviceErr := logsv0.NewLogsV0(&logsv0.LogsV0Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(logsService).ToNot(BeNil())

				// Construct an instance of the QueryOptions model
				queryOptionsModel := new(logsv0.GetBackgroundQueryDataOptions)
				queryOptionsModel.QueryID = core.UUIDPtr("1234-567-890")

				// Expect response parsing to fail since we are receiving a text/plain response
				logsService.GetBackgroundQueryData(queryOptionsModel, callBack{})
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})

	Describe(`Query(queryOptions *SubmitBackgroundQueryOptions) - Operation response error`, func() {
		queryPath := "/v1/background_query/1234-567-890/data"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(queryPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "text/event-stream")
					res.WriteHeader(200)
					fmt.Fprint(res, `} this is not valid json {`)
				}))
			})
			It(`Invoke Query with error: Operation response processing error`, func() {
				logsService, serviceErr := logsv0.NewLogsV0(&logsv0.LogsV0Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(logsService).ToNot(BeNil())

				// Construct an instance of the QueryOptions model
				queryOptionsModel := new(logsv0.GetBackgroundQueryDataOptions)
				queryOptionsModel.QueryID = core.UUIDPtr("1234-567-890")
				logsService.GetBackgroundQueryData(queryOptionsModel, callBack{})
			})
			AfterEach(func() {
				testServer.Close()
			})
		})

		Describe(`Query(queryOptions *SubmitBackgroundQueryOptions)`, func() {
			queryPath := "/v1/background_query/1234-567-890/data"
			Context(`Using mock server endpoint with timeout`, func() {
				BeforeEach(func() {
					testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
						defer GinkgoRecover()

						// Verify the contents of the request
						Expect(req.URL.EscapedPath()).To(Equal(queryPath))
						Expect(req.Method).To(Equal("GET"))

						// For gzip-disabled operation, verify Content-Encoding is not set.
						Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

						// If there is a body, then make sure we can read it
						bodyBuf := new(bytes.Buffer)
						if req.Header.Get("Content-Encoding") == "gzip" {
							body, err := core.NewGzipDecompressionReader(req.Body)
							Expect(err).To(BeNil())
							_, err = bodyBuf.ReadFrom(body)
							Expect(err).To(BeNil())
						} else {
							_, err := bodyBuf.ReadFrom(req.Body)
							Expect(err).To(BeNil())
						}
						fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

						// Sleep a short time to support a timeout test
						time.Sleep(100 * time.Millisecond)

						// Set mock response
						res.Header().Set("Content-type", "text/event-stream")
						res.WriteHeader(200)
						fmt.Fprintf(res, "%s", `{"error": {"message": "Message"}}`)
					}))
				})
				It(`Invoke Query successfully with retries`, func() {
					logsService, serviceErr := logsv0.NewLogsV0(&logsv0.LogsV0Options{
						URL:           testServer.URL,
						Authenticator: &core.NoAuthAuthenticator{},
					})
					Expect(serviceErr).To(BeNil())
					Expect(logsService).ToNot(BeNil())
					logsService.EnableRetries(0, 0)

					// Construct an instance of the QueryOptions model
					queryOptionsModel := new(logsv0.GetBackgroundQueryDataOptions)
					queryOptionsModel.QueryID = core.UUIDPtr("1234-567-890")

					// Invoke operation with a Context to test a timeout error
					ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
					defer cancelFunc()
					logsService.GetBackgroundQueryDataWithContext(ctx, queryOptionsModel, callBack{})

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
						Expect(req.URL.EscapedPath()).To(Equal(queryPath))
						Expect(req.Method).To(Equal("GET"))

						// For gzip-disabled operation, verify Content-Encoding is not set.
						Expect(req.Header.Get("Content-Encoding")).To(BeEmpty())

						// If there is a body, then make sure we can read it
						bodyBuf := new(bytes.Buffer)
						if req.Header.Get("Content-Encoding") == "gzip" {
							body, err := core.NewGzipDecompressionReader(req.Body)
							Expect(err).To(BeNil())
							_, err = bodyBuf.ReadFrom(body)
							Expect(err).To(BeNil())
						} else {
							_, err := bodyBuf.ReadFrom(req.Body)
							Expect(err).To(BeNil())
						}
						fmt.Fprintf(GinkgoWriter, "  Request body: %s", bodyBuf.String())

						// Set mock response
						res.Header().Set("Content-type", "text/event-stream")
						res.WriteHeader(200)
						fmt.Fprintf(res, "%s", `{"error": {"message": "Message"}}`)
					}))
				})
				It(`Invoke Query successfully`, func() {
					logsService, serviceErr := logsv0.NewLogsV0(&logsv0.LogsV0Options{
						URL:           testServer.URL,
						Authenticator: &core.NoAuthAuthenticator{},
					})
					Expect(serviceErr).To(BeNil())
					Expect(logsService).ToNot(BeNil())

					// Invoke operation with nil options model (negative test)
					logsService.Query(nil, callBack{})

					// Construct an instance of the QueryOptions model
					queryOptionsModel := new(logsv0.GetBackgroundQueryDataOptions)
					queryOptionsModel.QueryID = core.UUIDPtr("1234-567-890")

					// Invoke operation with valid options model (positive test)
					logsService.GetBackgroundQueryData(queryOptionsModel, callBack{})
				})
				It(`Invoke Query with error: Operation validation and request error`, func() {
					logsService, serviceErr := logsv0.NewLogsV0(&logsv0.LogsV0Options{
						URL:           testServer.URL,
						Authenticator: &core.NoAuthAuthenticator{},
					})
					Expect(serviceErr).To(BeNil())
					Expect(logsService).ToNot(BeNil())

					// Construct an instance of the QueryOptions model
					queryOptionsModel := new(logsv0.GetBackgroundQueryDataOptions)
					queryOptionsModel.QueryID = core.UUIDPtr("1234-567-890")

					// Invoke operation with empty URL (negative test)
					err := logsService.SetServiceURL("")
					Expect(err).To(BeNil())
					logsService.GetBackgroundQueryData(queryOptionsModel, callBack{})
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
				It(`Invoke Query successfully`, func() {
					logsService, serviceErr := logsv0.NewLogsV0(&logsv0.LogsV0Options{
						URL:           testServer.URL,
						Authenticator: &core.NoAuthAuthenticator{},
					})
					Expect(serviceErr).To(BeNil())
					Expect(logsService).ToNot(BeNil())

					// Construct an instance of the QueryOptions model
					queryOptionsModel := new(logsv0.GetBackgroundQueryDataOptions)
					queryOptionsModel.QueryID = core.UUIDPtr("1234-567-890")

					// Invoke operation
					logsService.GetBackgroundQueryData(queryOptionsModel, callBack{})
				})
				AfterEach(func() {
					testServer.Close()
				})
			})
		})
		Context(`Using mock server endpoint with valid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(queryPath))
					Expect(req.Method).To(Equal("GET"))
					res.Header().Set("Content-type", "text/event-stream")
					res.WriteHeader(200)
					fmt.Println(backgroundQueryEventTestData)
					fmt.Fprint(res, backgroundQueryEventTestData)
				}))
			})
			It(`Invoke Query with error: Operation response processing error`, func() {
				logsService, serviceErr := logsv0.NewLogsV0(&logsv0.LogsV0Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(logsService).ToNot(BeNil())

				// Construct an instance of the QueryOptions model
				// Construct an instance of the QueryOptions model
				queryOptionsModel := new(logsv0.GetBackgroundQueryDataOptions)
				queryOptionsModel.QueryID = core.UUIDPtr("1234-567-890")

				// Expect response parsing to fail since we are receiving a text/plain response
				logsService.GetBackgroundQueryData(queryOptionsModel, callBack{})

			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
})
