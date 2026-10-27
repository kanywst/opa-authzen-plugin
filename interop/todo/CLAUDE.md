# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in `interop/todo/`. Commands below run from this directory.

## What This Is

OPA-based PDP (Policy Decision Point) for the OpenID AuthZEN interop test suite. Implements a Todo application authorization policy using Rego, designed to pass the [AuthZEN Interop Test Suite](https://github.com/openid/authzen/tree/main/interop/authzen-todo-backend). The PDP runs via [opa-authzen-plugin](https://github.com/kanywst/opa-authzen-plugin).

## Commands

### Run all tests (rego + integration)

```bash
make test
```

### Run Rego unit tests only (no PDP required)

```bash
make rego-test
```

### Start/stop PDP

```bash
make up      # docker compose up
make down    # docker compose down
```

### Run integration tests against an already-running PDP

```bash
./scripts/test-local.sh [pdp-url]   # default: http://localhost:8181
```

### Start PDP from local binary (dev)

```bash
./scripts/start-pdp.sh [path-to-binary]
# Default: ../../opa-authzen-plugin (run `make build` at the repository root first)
```

## Architecture

The policy receives AuthZEN-shaped JSON input via the opa-authzen-plugin, which registers AuthZEN routes (`/access/v1/evaluation`, `/access/v1/evaluations`, `/access/v1/search/{subject,resource,action}`, `/.well-known/authzen-configuration`) directly on OPA's HTTP server (port 8181).

**Policy resolution flow:**

1. `input.subject.id` (a base64-encoded PID) is looked up in `data/users.json` to get the user's email and roles
2. `input.action.name` determines which authorization rule applies
3. For ownership-scoped actions (`can_update_todo`, `can_delete_todo`), `input.resource.properties.ownerID` is compared against the user's email

**Role model:** Three roles — `admin` (+ `evil_genius` for Rick), `editor`, `viewer`. Admins can do everything. Editors can create todos and update/delete their own. Viewers can only read.

**Key detail:** The `evil_genius` role grants the same update permissions as `admin` — this is a separate Rego rule in `policy/authzen.rego` needed to pass the interop tests for Rick's update scenarios.

## Config

`config.yaml` configures the opa-authzen-plugin: routes to the `authzen` package and reads the `allow` decision. All endpoints are served on OPA's default port (8181). Beyond `path`/`decision` it sets the following, each of which the e2e suite asserts:

- `search` — names the Rego rules backing the Subject/Resource/Action Search APIs (`subject_search`, `resource_search`, `action_search`). Needs plugin 0.3+.
- `decision_context` — names the `decision_context` rule, returned as the Decision's optional `context` member (spec Section 5.5.1). Needs plugin 0.5+.
- `capabilities` — operator-supplied PDP capability URNs in the metadata document (Section 9.1.2). Needs plugin 0.4+.
- `supported_obligations` — opts into the Obligations Profile 1.0. Needs plugin 0.6+.
- `access_request_endpoint` / `jwks_uri` — Access Request and Approval discovery members. Needs plugin 0.7+.
- `signed_metadata` — a fixture JWT published in the metadata document (Section 9.1.3). Its claims must agree with the keys above or the plugin refuses to start, so change them together. Needs plugin 0.10+.

The suite also asserts behavior with no config key behind it: since 0.8, a batch request without an `evaluations` array (or with an empty one) gets the singular `{"decision": ...}` response, and `Content-Type` matches case-insensitively.

`make test-interop` at the repository root runs this suite against the image it just built, overriding `PDP_VERSION`. The pin in the `Makefile` (and the default in `docker-compose.yaml`) only matters for a standalone `make test` here, and must stay at or above the highest of those. When the plugin gains config surface, extend `config.yaml`, `policy/authzen.rego`, and `scripts/test-local.sh` in the same pull request — a feature the plugin ships but this suite never exercises is a feature nothing validates.

## Decision context and obligations

`decision_context` in `policy/authzen.rego` is the union of three parts, each defaulting to `{}` so the plugin can omit `context` when there is nothing to say:

- `reason_context` — always present; a stable token (`permitted`, `not_permitted`, `unknown_subject`), never prose.
- `obligation_context` — a `notification` obligation when a privileged subject (admin or `evil_genius`) mutates a todo somebody else owns. Gated on `"notification" in input.context.supported_obligations`, which is the profile's negotiation rule.
- `negotiation_context` — echoes `input.context.supported_obligations` as `negotiated_obligations`. This exists so the e2e suite can observe the plugin's negotiation filter from outside the PDP; without it, "the plugin dropped an unadvertised type before Rego saw it" is unobservable over HTTP.

The plugin filters `context.supported_obligations` down to the `supported_obligations` list in `config.yaml` before the policy runs, so anything the policy sees in that array is a type this PDP advertises.

## CI

The `e2e` job in the repository's `.github/workflows/ci.yaml` runs `make test-interop-rego` (`check`, `fmt --fail --diff`, and `test` through the plugin binary, so the policy is checked with the OPA the plugin links) and then `make test-interop`. The `conformance` job's `make test-harness` also serves `policy/` and `data/` to the working group's Todo harness.

## Search rule semantics

Each `*_search` rule in `policy/authzen.rego` re-invokes `allow` against candidate entities so search results stay consistent with single-evaluation decisions:

- `subject_search` iterates over `data.users` and asks "if this user were the subject, would `allow` permit the input action/resource?"
- `resource_search` iterates over `data.todos` and asks the same for resources.
- `action_search` iterates over `known_actions` (the modeled action set) and asks the same for actions.

`data/todos.json` provides the resource catalog for `resource_search`. Update it (and the unit tests in `policy/authzen_test.rego`) when the modeled todo set changes.
