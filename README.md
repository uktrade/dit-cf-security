# dit-cf-security [![CircleCI](https://circleci.com/gh/uktrade/dit-cf-security.svg?style=svg)](https://circleci.com/gh/uktrade/dit-cf-security) [![Test Coverage](https://api.codeclimate.com/v1/badges/2e18d6693c2c9dcd4d3e/test_coverage)](https://codeclimate.com/github/uktrade/dit-cf-security/test_coverage)

An IP filtering route service that provides a basic auth bypass for automated testing tools.

## Usage

Push this route-service to cloudfoundry

`$ cf push ip-filter-service`

Create a user provided service

`cf create-user-provided-service test-route-service -r https://<ROUTE-SERVICE-ADDRESS>`

Bind to your application

`$ cf bind-route-service <APPLICATION-DOMAIN> test-route-service --hostname <APPLICATION-HOST>`

