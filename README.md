# Manual JWT Authentication to get Access Token from Service Account JSON file for Google Cloud (Go)

A lightweight, dependency-free implementation to manually get an OAuth 2.0 Access Token using a Service Account JSON file in Go.

## Why?
I created this file while working on some feature for noon app test builds flow, where I needed to authenticate to Google Cloud Firestore in GitHub Actions. There is already an action you can use to authenticate [repo](https://github.com/google-github-actions/auth) but I wanted to avoid adding extra dependencies to the workflow and to learn something new.

## How to Use
1. Save your Service Account JSON file securely (e.g., as a GitHub Secret).
2. In the workflow, read the GitHub Secret and write it to a temporary file.
3. Replace `SERVICE_NAME` in the Scope constant with the appropriate Google Cloud service you want to access (e.g., `https://www.googleapis.com/auth/datastore`).
4. Use the provided Go code to read the JSON file, create a JWT, sign it, and exchange it for an Access Token.
5. Use the Access Token to authenticate your requests to Google Cloud services.

## License
This code is licensed under the MIT License. See the [LICENSE](LICENSE) file for details

