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
	eventTestData = "data: {\"result\": {\"results\": []}}\n\n"
)

type callBack struct{}

func (cb callBack) OnClose() {
}

func (cb callBack) OnError(err error) {
	Expect(err).ToNot(BeNil())
}

func (cb callBack) OnData(detailedResponse *core.DetailedResponse) {
	Expect(detailedResponse.RawResult).ToNot(BeNil())
	Expect(detailedResponse.Result).ToNot(BeNil())
}

var _ = Describe(`LogsV1`, func() {
	var testServer *httptest.Server
	Describe(`Query(queryOptions *QueryOptions) - Operation response error`, func() {
		queryPath := "/v1/dataprime/query/run"
		Context(`Using mock server endpoint with invalid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(queryPath))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "application/json")
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

				// Construct an instance of the ApisDataprimeV1Metadata model
				apisDataprimeV1MetadataModel := new(logsv0.ApisDataprimeV1Metadata)
				apisDataprimeV1MetadataModel.StartDate = CreateMockDateTime("2019-01-01T12:00:00.000Z")
				apisDataprimeV1MetadataModel.EndDate = CreateMockDateTime("2019-01-01T12:00:00.000Z")
				apisDataprimeV1MetadataModel.DefaultSource = core.StringPtr("testString")
				apisDataprimeV1MetadataModel.Tier = core.StringPtr("unspecified")
				apisDataprimeV1MetadataModel.Syntax = core.StringPtr("unspecified")
				apisDataprimeV1MetadataModel.Limit = core.Int64Ptr(int64(38))
				apisDataprimeV1MetadataModel.StrictFieldsValidation = core.BoolPtr(true)

				// Construct an instance of the QueryOptions model
				queryOptionsModel := new(logsv0.QueryOptions)
				queryOptionsModel.Query = core.StringPtr("testString")
				queryOptionsModel.Metadata = apisDataprimeV1MetadataModel
				queryOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				logsService.Query(queryOptionsModel, callBack{})

			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`Query(queryOptions *QueryOptions)`, func() {
		queryPath := "/v1/dataprime/query/run"
		Context(`Using mock server endpoint with timeout`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(queryPath))
					Expect(req.Method).To(Equal("POST"))

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

				// Construct an instance of the ApisDataprimeV1Metadata model
				apisDataprimeV1MetadataModel := new(logsv0.ApisDataprimeV1Metadata)
				apisDataprimeV1MetadataModel.StartDate = CreateMockDateTime("2019-01-01T12:00:00.000Z")
				apisDataprimeV1MetadataModel.EndDate = CreateMockDateTime("2019-01-01T12:00:00.000Z")
				apisDataprimeV1MetadataModel.DefaultSource = core.StringPtr("testString")
				apisDataprimeV1MetadataModel.Tier = core.StringPtr("unspecified")
				apisDataprimeV1MetadataModel.Syntax = core.StringPtr("unspecified")
				apisDataprimeV1MetadataModel.Limit = core.Int64Ptr(int64(38))
				apisDataprimeV1MetadataModel.StrictFieldsValidation = core.BoolPtr(true)

				// Construct an instance of the QueryOptions model
				queryOptionsModel := new(logsv0.QueryOptions)
				queryOptionsModel.Query = core.StringPtr("testString")
				queryOptionsModel.Metadata = apisDataprimeV1MetadataModel
				queryOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with a Context to test a timeout error
				ctx, cancelFunc := context.WithTimeout(context.Background(), 80*time.Millisecond)
				defer cancelFunc()
				logsService.QueryWithContext(ctx, queryOptionsModel, callBack{})

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
					Expect(req.Method).To(Equal("POST"))

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

				// Construct an instance of the ApisDataprimeV1Metadata model
				apisDataprimeV1MetadataModel := new(logsv0.ApisDataprimeV1Metadata)
				apisDataprimeV1MetadataModel.StartDate = CreateMockDateTime("2019-01-01T12:00:00.000Z")
				apisDataprimeV1MetadataModel.EndDate = CreateMockDateTime("2019-01-01T12:00:00.000Z")
				apisDataprimeV1MetadataModel.DefaultSource = core.StringPtr("testString")
				apisDataprimeV1MetadataModel.Tier = core.StringPtr("unspecified")
				apisDataprimeV1MetadataModel.Syntax = core.StringPtr("unspecified")
				apisDataprimeV1MetadataModel.Limit = core.Int64Ptr(int64(38))
				apisDataprimeV1MetadataModel.StrictFieldsValidation = core.BoolPtr(true)

				// Construct an instance of the QueryOptions model
				queryOptionsModel := new(logsv0.QueryOptions)
				queryOptionsModel.Query = core.StringPtr("testString")
				queryOptionsModel.Metadata = apisDataprimeV1MetadataModel
				queryOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation with valid options model (positive test)
				logsService.Query(queryOptionsModel, callBack{})
			})
			It(`Invoke Query with error: Operation validation and request error`, func() {
				logsService, serviceErr := logsv0.NewLogsV0(&logsv0.LogsV0Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(logsService).ToNot(BeNil())

				// Construct an instance of the ApisDataprimeV1Metadata model
				apisDataprimeV1MetadataModel := new(logsv0.ApisDataprimeV1Metadata)
				apisDataprimeV1MetadataModel.StartDate = CreateMockDateTime("2019-01-01T12:00:00.000Z")
				apisDataprimeV1MetadataModel.EndDate = CreateMockDateTime("2019-01-01T12:00:00.000Z")
				apisDataprimeV1MetadataModel.DefaultSource = core.StringPtr("testString")
				apisDataprimeV1MetadataModel.Tier = core.StringPtr("unspecified")
				apisDataprimeV1MetadataModel.Syntax = core.StringPtr("unspecified")
				apisDataprimeV1MetadataModel.Limit = core.Int64Ptr(int64(38))
				apisDataprimeV1MetadataModel.StrictFieldsValidation = core.BoolPtr(true)

				// Construct an instance of the QueryOptions model
				queryOptionsModel := new(logsv0.QueryOptions)
				queryOptionsModel.Query = core.StringPtr("testString")
				queryOptionsModel.Metadata = apisDataprimeV1MetadataModel
				queryOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Invoke operation with empty URL (negative test)
				err := logsService.SetServiceURL("")
				Expect(err).To(BeNil())
				logsService.Query(queryOptionsModel, callBack{})
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

				// Construct an instance of the ApisDataprimeV1Metadata model
				apisDataprimeV1MetadataModel := new(logsv0.ApisDataprimeV1Metadata)
				apisDataprimeV1MetadataModel.StartDate = CreateMockDateTime("2019-01-01T12:00:00.000Z")
				apisDataprimeV1MetadataModel.EndDate = CreateMockDateTime("2019-01-01T12:00:00.000Z")
				apisDataprimeV1MetadataModel.DefaultSource = core.StringPtr("testString")
				apisDataprimeV1MetadataModel.Tier = core.StringPtr("unspecified")
				apisDataprimeV1MetadataModel.Syntax = core.StringPtr("unspecified")
				apisDataprimeV1MetadataModel.Limit = core.Int64Ptr(int64(38))
				apisDataprimeV1MetadataModel.StrictFieldsValidation = core.BoolPtr(true)

				// Construct an instance of the QueryOptions model
				queryOptionsModel := new(logsv0.QueryOptions)
				queryOptionsModel.Query = core.StringPtr("testString")
				queryOptionsModel.Metadata = apisDataprimeV1MetadataModel
				queryOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}

				// Invoke operation
				logsService.Query(queryOptionsModel, callBack{})
			})
			AfterEach(func() {
				testServer.Close()
			})
		})
		Context(`Using mock server endpoint with valid JSON response`, func() {
			BeforeEach(func() {
				testServer = httptest.NewServer(http.HandlerFunc(func(res http.ResponseWriter, req *http.Request) {
					defer GinkgoRecover()

					// Verify the contents of the request
					Expect(req.URL.EscapedPath()).To(Equal(queryPath))
					Expect(req.Method).To(Equal("POST"))
					res.Header().Set("Content-type", "text/event-stream")
					res.WriteHeader(200)
					fmt.Fprint(res, eventTestData)
				}))
			})
			It(`Invoke Query with error: Operation response processing error`, func() {
				logsService, serviceErr := logsv0.NewLogsV0(&logsv0.LogsV0Options{
					URL:           testServer.URL,
					Authenticator: &core.NoAuthAuthenticator{},
				})
				Expect(serviceErr).To(BeNil())
				Expect(logsService).ToNot(BeNil())

				// Construct an instance of the ApisDataprimeV1Metadata model
				apisDataprimeV1MetadataModel := new(logsv0.ApisDataprimeV1Metadata)
				apisDataprimeV1MetadataModel.StartDate = CreateMockDateTime("2019-01-01T12:00:00.000Z")
				apisDataprimeV1MetadataModel.EndDate = CreateMockDateTime("2019-01-01T12:00:00.000Z")
				apisDataprimeV1MetadataModel.DefaultSource = core.StringPtr("testString")
				apisDataprimeV1MetadataModel.Tier = core.StringPtr("unspecified")
				apisDataprimeV1MetadataModel.Syntax = core.StringPtr("unspecified")
				apisDataprimeV1MetadataModel.Limit = core.Int64Ptr(int64(38))
				apisDataprimeV1MetadataModel.StrictFieldsValidation = core.BoolPtr(true)

				// Construct an instance of the QueryOptions model
				queryOptionsModel := new(logsv0.QueryOptions)
				queryOptionsModel.Query = core.StringPtr("testString")
				queryOptionsModel.Metadata = apisDataprimeV1MetadataModel
				queryOptionsModel.Headers = map[string]string{"x-custom-header": "x-custom-value"}
				// Expect response parsing to fail since we are receiving a text/plain response
				logsService.Query(queryOptionsModel, callBack{})

			})
			AfterEach(func() {
				testServer.Close()
			})
		})
	})
	Describe(`Model constructor tests`, func() {
		Context(`Using a service client instance`, func() {
			logsService, _ := logsv0.NewLogsV0(&logsv0.LogsV0Options{
				URL:           "http://logsv0modelgenerator.com",
				Authenticator: &core.NoAuthAuthenticator{},
			})
			It(`Invoke NewQueryOptions successfully`, func() {
				// Construct an instance of the ApisDataprimeV1Metadata model
				apisDataprimeV1MetadataModel := new(logsv0.ApisDataprimeV1Metadata)
				Expect(apisDataprimeV1MetadataModel).ToNot(BeNil())
				apisDataprimeV1MetadataModel.StartDate = CreateMockDateTime("2019-01-01T12:00:00.000Z")
				apisDataprimeV1MetadataModel.EndDate = CreateMockDateTime("2019-01-01T12:00:00.000Z")
				apisDataprimeV1MetadataModel.DefaultSource = core.StringPtr("testString")
				apisDataprimeV1MetadataModel.Tier = core.StringPtr("unspecified")
				apisDataprimeV1MetadataModel.Syntax = core.StringPtr("unspecified")
				apisDataprimeV1MetadataModel.Limit = core.Int64Ptr(int64(38))
				apisDataprimeV1MetadataModel.StrictFieldsValidation = core.BoolPtr(true)
				Expect(apisDataprimeV1MetadataModel.StartDate).To(Equal(CreateMockDateTime("2019-01-01T12:00:00.000Z")))
				Expect(apisDataprimeV1MetadataModel.EndDate).To(Equal(CreateMockDateTime("2019-01-01T12:00:00.000Z")))
				Expect(apisDataprimeV1MetadataModel.DefaultSource).To(Equal(core.StringPtr("testString")))
				Expect(apisDataprimeV1MetadataModel.Tier).To(Equal(core.StringPtr("unspecified")))
				Expect(apisDataprimeV1MetadataModel.Syntax).To(Equal(core.StringPtr("unspecified")))
				Expect(apisDataprimeV1MetadataModel.Limit).To(Equal(core.Int64Ptr(int64(38))))
				Expect(apisDataprimeV1MetadataModel.StrictFieldsValidation).To(Equal(core.BoolPtr(true)))

				// Construct an instance of the QueryOptions model
				queryOptionsModel := logsService.NewQueryOptions()
				queryOptionsModel.SetQuery("testString")
				queryOptionsModel.SetMetadata(apisDataprimeV1MetadataModel)
				queryOptionsModel.SetHeaders(map[string]string{"foo": "bar"})
				Expect(queryOptionsModel).ToNot(BeNil())
				Expect(queryOptionsModel.Query).To(Equal(core.StringPtr("testString")))
				Expect(queryOptionsModel.Metadata).To(Equal(apisDataprimeV1MetadataModel))
				Expect(queryOptionsModel.Headers).To(Equal(map[string]string{"foo": "bar"}))
			})
		})
	})
})
