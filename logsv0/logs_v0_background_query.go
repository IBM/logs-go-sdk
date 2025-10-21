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

/*
 * IBM OpenAPI SDK Code Generator Version: 3.84.0-a4533f12-20240103-170852
 */

// Package logsv0 : Operations and models for the LogsV0 service
package logsv0

import (
	"bufio"
	"context"
	"fmt"
	"io"

	"github.com/IBM/go-sdk-core/v5/core"
	"github.com/go-openapi/strfmt"
	common "github.com/IBM/logs-go-sdk/common"
)

// GetBackgroundQueryDataOptions : The GetBackgroundQueryData options.
type GetBackgroundQueryDataOptions struct {
	// Generated query ID that can be later used to obtain status and results.
	QueryID *strfmt.UUID `json:"query_id" validate:"required"`

	// Allows users to set headers on API requests.
	Headers map[string]string
}

type BGQueryResponseStreamItem struct {
	Response ResponseData `json:"response"`
}

type ResponseData struct {
	Results InnerResults `json:"results"`
}

type InnerResults struct {
	Results []ApisDataprimeV1DataprimeResults `json:"results,omitempty"`
}

// NewGetBackgroundQueryDataOptions : Instantiate GetBackgroundQueryDataOptions
func (*LogsV0) NewGetBackgroundQueryDataOptions(queryID *strfmt.UUID) *GetBackgroundQueryDataOptions {
	return &GetBackgroundQueryDataOptions{
		QueryID: queryID,
	}
}

// SetQueryID : Allow user to set QueryID
func (_options *GetBackgroundQueryDataOptions) SetQueryID(queryID *strfmt.UUID) *GetBackgroundQueryDataOptions {
	_options.QueryID = queryID
	return _options
}

// SetHeaders : Allow user to set Headers
func (options *GetBackgroundQueryDataOptions) SetHeaders(param map[string]string) *GetBackgroundQueryDataOptions {
	options.Headers = param
	return options
}

// GetBackgroundQueryData : Get the data of a background query
// Get the data of a background query.
func (logs *LogsV0) GetBackgroundQueryData(getBackgroundQueryDataOptions *GetBackgroundQueryDataOptions, callBack QueryCallBack) {
	logs.GetBackgroundQueryDataWithContext(context.Background(), getBackgroundQueryDataOptions, callBack)
}

// GetBackgroundQueryDataWithContext is an alternate form of the GetBackgroundQueryData method which supports a Context parameter
func (logs *LogsV0) GetBackgroundQueryDataWithContext(ctx context.Context, getBackgroundQueryDataOptions *GetBackgroundQueryDataOptions, callBack QueryCallBack) {

	err := core.ValidateNotNil(getBackgroundQueryDataOptions, "getBackgroundQueryDataOptions cannot be nil")
	if err != nil {
		err = core.SDKErrorf(err, "", "unexpected-nil-param", common.GetComponentInfo())
		return
	}
	err = core.ValidateStruct(getBackgroundQueryDataOptions, "getBackgroundQueryDataOptions")
	if err != nil {
		err = core.SDKErrorf(err, "", "struct-validation-error", common.GetComponentInfo())
		return
	}

	pathParamsMap := map[string]string{
		"query_id": fmt.Sprint(*getBackgroundQueryDataOptions.QueryID),
	}

	builder := core.NewRequestBuilder(core.GET)
	builder = builder.WithContext(ctx)
	builder.EnableGzipCompression = logs.GetEnableGzipCompression()
	_, err = builder.ResolveRequestURL(logs.Service.Options.URL, `/v1/background_query/{query_id}/data`, pathParamsMap)
	if err != nil {
		err = core.SDKErrorf(err, "", "url-resolve-error", common.GetComponentInfo())
		return
	}

	for headerName, headerValue := range getBackgroundQueryDataOptions.Headers {
		builder.AddHeader(headerName, headerValue)
	}

	sdkHeaders := common.GetSdkHeaders("logs", "V0", "GetBackgroundQueryData")
	for headerName, headerValue := range sdkHeaders {
		builder.AddHeader(headerName, headerValue)
	}
	builder.AddHeader("Accept", "text/event-stream")

	request, err := builder.Build()
	if err != nil {
		err = core.SDKErrorf(err, "", "build-error", common.GetComponentInfo())
		return
	}

	var rawResponse io.ReadCloser
	response, err := logs.Service.Request(request, &rawResponse)
	if err != nil {
		callBack.OnError(err)
		return
	}

	reader := bufio.NewReader(response.Result.(io.ReadCloser))

	queryListener := &QueryListener{
		closed:   make(chan bool, 1),
		callback: callBack,
	}

	go queryListener.readEventLoop(ctx, reader, response, true)

	queryListener.OnClose()
}
