[![Build Status](https://v3.travis-ci.com/IBM/logs-go-sdk.svg?token=Z799xXryYYPor3yyJxEs&branch=main)](https://v3.travis.ibm.com/IBM/logs-go-sdk)
[![semantic-release](https://img.shields.io/badge/%20%20%F0%9F%93%A6%F0%9F%9A%80-semantic--release-e10079.svg)](https://github.com/semantic-release/semantic-release)

# IBM Cloud Logs Services Go SDK 0.1.1
Go client library to interact with the various [IBM Cloud Logs Services APIs](https://cloud.ibm.com/apidocs?category=logs).

Disclaimer: this SDK is being released initially as a **pre-release** version.
Changes might occur which impact applications that use this SDK.

## Table of Contents
<!--
  The TOC below is generated using the `markdown-toc` node package.

      https://github.com/jonschlinkert/markdown-toc

  You should regenerate the TOC after making changes to this file.

      npx markdown-toc -i README.md
  -->

<!-- toc -->

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
  * [Go modules](#go-modules)
  * [`go get` command](#go-get-command)
- [Using the SDK](#using-the-sdk)
- [Questions](#questions)
- [Issues](#issues)
- [Open source @ IBM](#open-source--ibm)
- [Contributing](#contributing)
- [License](#license)

<!-- tocstop -->

## Overview

The IBM Cloud Logs Services Go SDK allows developers to programmatically interact with the following IBM Cloud services:

Service Name | Package name 
--- | --- 
[logs](https://test.cloud.ibm.com/apidocs/cloud-logs-service-api/cloud-logs-v1-beta) | logsv0

## Prerequisites

[ibm-cloud-onboarding]: https://cloud.ibm.com/registration

* An [IBM Cloud][ibm-cloud-onboarding] account.
* An IAM API key to allow the SDK to access your account. Create one [here](https://cloud.ibm.com/iam/apikeys).
* Go version 1.19 or above.

## Installation
The current version of this SDK: 0.1.1

### Go modules  
If your application uses Go modules for dependency management (recommended), just add an import for each service 
that you will use in your application.  
Here is an example:

```go
import (
	"github.com/IBM/logs-go-sdk/logsv0"
)
```
Next, run `go build` or `go mod tidy` to download and install the new dependencies and update your application's
`go.mod` file.  

In the example above, the `logsv0` part of the import path is the package name
associated with the Logs service.
See the service table above to find the approprate package name for the services used by your application.

### `go get` command  
Alternatively, you can use the `go get` command to download and install the appropriate packages needed by your application:
```
go get -u github.com/IBM/logs-go-sdk/logsv0
```
Be sure to use the appropriate package name from the service table above for the services used by your application.

## Using the SDK
Examples are available [here](https://github.com/IBM/logs-go-sdk/tree/main/example/v0/README.md).
For general SDK usage information, please see [this link](https://github.com/IBM/ibm-cloud-sdk-common/blob/main/README.md)

## Questions

If you are having difficulties using this SDK or have a question about the IBM Cloud services,
please ask a question at 
[Stack Overflow](http://stackoverflow.com/questions/ask?tags=ibm-cloud).

## Issues
If you encounter an issue with the project, you are welcome to submit a
[bug report](https://github.com/IBM/logs-go-sdk/issues).
Before that, please search for similar issues. It's possible that someone has already reported the problem.

## Open source @ IBM
Find more open source projects on the [IBM Github Page](http://ibm.github.io/)

## Contributing
See [CONTRIBUTING](CONTRIBUTING.md).

## License

This SDK project is released under the Apache 2.0 license.
The license's full text can be found in [LICENSE](LICENSE).
