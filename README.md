# dit-cf-security [![CircleCI](https://circleci.com/gh/uktrade/dit-cf-security.svg?style=svg)](https://circleci.com/gh/uktrade/dit-cf-security) [![Test Coverage](https://api.codeclimate.com/v1/badges/2e18d6693c2c9dcd4d3e/test_coverage)](https://codeclimate.com/github/uktrade/dit-cf-security/test_coverage)

A configurable route service that allows access to applications based on combinations of

- basic auth [for automated testing tools],
- IP address [based on a configurable index in the `x-forwarded-for` header],
- shared secret in an HTTP header [passed from a CDN],
- requested host name.

All requests are routed to the IP address(es) of a single host that should resolve to the Cloud Foundry router. This is to support persistent onward connections, to avoid routing requests back through a CDN, and to avoid routing requests to arbitrary targets on the internet as part of a defense-in-depth/least-privilege strategy.

The service is configured with a number of _routes_. For each route, multiple allowed shared secret and basic auth credentials are supported to allow for credential rotation. These routes can match Cloud Foundry routes, but they don't have to; for example to allow the same basic auth credentials across domains.

Any header defined as a shared secret header is not forwarded to the origin, even if defined in a non-matching route.


## Usage

Push this route-service to Cloud Foundry [GOV.UK PaaS]

`$ cf push ip-filter-service`

Create a user provided service

`cf create-user-provided-service test-route-service -r https://<ROUTE-SERVICE-ADDRESS>`

Bind to your application

`$ cf bind-route-service <APPLICATION-DOMAIN> test-route-service --hostname <APPLICATION-HOST>`


## Configuration

Configuration is done via sets of environment variables, where each set defines a route. If a request isn't allowed by the settings of a route, the next is checked until one is found that does allow it. If no route matches a request, a 403 is returned with an error page.

In the following, `i`, `j`, `k` and `l` can be any whole number.

| Variable                 |  Description | Example |
| ---                      | ---          | ---     |
| `ROUTES__i__HOSTNAME_REGEX`| A regular expression to match against the hostname |`^my\.domain\.com$`
| `ROUTES__i__IP_DETERMINED_BY_X_FORWARDED_FOR_INDEX` | The index of the IP addresses in the `x-forwarded-for` header to trust as the client's IP address | `-3`
| `ROUTES__i__IP_RANGES__j` | A CIDR range to match against the client IP. At least one is required per route | `1.2.3.4/32`
| `ROUTES__i__BASIC_AUTH__k__USERNAME` | A basic auth username | _not shown_
| `ROUTES__i__BASIC_AUTH__k__PASSWORD` | A basic auth password | _not shown_
| `ROUTES__i__BASIC_AUTH__k__AUTHENTICATE_PATH` | A path to force the server to return a 401 and `WWW-Authenticate` header | `/__authenticate`
| `ROUTES__i__SHARED_SECRET_HEADER__l__NAME` | The name of the HTTP header which must contain a secret value | `x-cdn-secret`
| `ROUTES__i__SHARED_SECRET_HEADER__l__VALUE` | The required secret value in the HTTP header | _not shown_

The following are settings that apply globally.

| Variable                 |  Description | Example |
| ---                      | ---          | ---     |
| `ORIGIN_HOSTNAME`| The origin host that all requests are routed to | `some-domain-under.cloud-foundry-router.test`
| `ORIGIN_PROTO` | The protocol used to communicate to the origin | `https`
| `EMAIL` | The email address shown to users on authorisation failure | `my.email@domain.test`
| `LOG_LEVEL` | The Python log level | `INFO`
| `PORT` | The port for the application to listen on, typically populated automatically by Cloud Foundry | `8080`
