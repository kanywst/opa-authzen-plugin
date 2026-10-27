# Interop Todo PDP

An OPA + Rego PDP implementation for the [OpenID AuthZEN interop](https://authzen-interop.net/) Todo scenario, served by this plugin. It used to live in the separate `kanywst/opa-authzen-interop` repository; it moved here so that a plugin change and the e2e assertions covering it land in the same pull request.

- **Spec:** [Authorization API 1.0](https://openid.github.io/authzen/)
- **Interop site:** [authzen-interop.net](https://authzen-interop.net)
- **Test harness:** [openid/authzen/interop/authzen-todo-backend](https://github.com/openid/authzen/tree/main/interop/authzen-todo-backend)

Requires opa-authzen-plugin **0.10 or newer**: the config here enables Search (0.3), capability URNs in the PDP metadata (0.4), decision context (0.5), the Obligations Profile (0.6), the Access Request and Approval discovery members (0.7), and signed metadata (0.10). The e2e suite also asserts two 0.8 behaviors: the singular response to a batch request without evaluations, and case-insensitive `Content-Type` matching.

## Usage

### Quick start

```bash
make test
```

This runs Rego unit tests, starts the PDP via Docker Compose, runs integration tests, and stops the PDP.

To run only the Rego unit tests (no Docker required):

```bash
make rego-test
```

### Running the AuthZEN interop test harness

Start the PDP, then use the [authzen-todo-backend](https://github.com/openid/authzen/tree/main/interop/authzen-todo-backend) test harness:

```bash
make up

git clone https://github.com/openid/authzen.git
cd authzen/interop/authzen-todo-backend
yarn install && yarn build

# authorization-api-1_0-01: single evaluation
yarn test http://localhost:8181 authorization-api-1_0-01 console
```

### Using the binary (development)

```bash
git clone https://github.com/kanywst/opa-authzen-plugin.git
cd opa-authzen-plugin && make build
cd interop/todo

# run the tests
./scripts/start-pdp.sh
./scripts/test-local.sh
```

## Todo scenario

5 users (Rick & Morty themed) and 5 authorization actions. See [Todo interop scenario](https://authzen-interop.net/docs/scenarios/todo-1.1/) for request/response details.

| Action            | admin (Rick) | editor (Morty, Summer) | viewer (Beth, Jerry) |
| ----------------- | :----------: | :--------------------: | :------------------: |
| `can_read_user`   |    allow     |         allow          |        allow         |
| `can_read_todos`  |    allow     |         allow          |        allow         |
| `can_create_todo` |    allow     |         allow          |       **deny**       |
| `can_update_todo` | allow (any)  |    allow (own only)    |       **deny**       |
| `can_delete_todo` | allow (any)  |    allow (own only)    |       **deny**       |

## Endpoints

| Endpoint           | Path                                     | Status      |
| ------------------ | ---------------------------------------- | ----------- |
| Evaluation         | `POST /access/v1/evaluation`             | implemented |
| Evaluations(batch) | `POST /access/v1/evaluations`            | implemented |
| Subject Search     | `POST /access/v1/search/subject`         | implemented |
| Resource Search    | `POST /access/v1/search/resource`        | implemented |
| Action Search      | `POST /access/v1/search/action`          | implemented |
| PDP Metadata       | `GET /.well-known/authzen-configuration` | implemented |

The Search APIs are enabled via the `search` block in `config.yaml`, which points the plugin at the `subject_search`, `resource_search`, and `action_search` rules in `policy/authzen.rego`. Pagination is supported via the opaque `page.next_token`.

The metadata document also advertises a `capabilities` array (spec Section 9.1.2) and a `supported_obligations` array (Obligations Profile 1.0), both sourced from `config.yaml`.

## Decision context and obligations

`config.yaml` sets `decision_context: decision_context`, so every Decision carries the optional `context` member (spec Section 5.5.1) built by the rule of the same name in `policy/authzen.rego`. It always includes a short machine-readable `reason` — `permitted`, `not_permitted`, or `unknown_subject` — so a PEP can branch without parsing prose.

The scenario also implements the [AuthZEN Obligations Profile 1.0](https://openid.github.io/authzen/authzen-obligations-profile-1_0.html). When a privileged subject (admin or `evil_genius`) updates or deletes a todo somebody else owns, the permit carries a `notification` obligation naming the owner to be told:

```json
{
  "decision": true,
  "context": {
    "reason": "permitted",
    "negotiated_obligations": ["notification"],
    "obligations": [{
      "id": "notify-owner-7240d0db-8ff0-41ec-98b2-34a096273b91",
      "type": "notification",
      "properties": {
        "recipient": "morty@the-citadel.com",
        "event": "can_update_todo",
        "actor": "rick@the-citadel.com"
      }
    }]
  }
}
```

The profile requires a PDP to ignore any Obligation Type in the PEP's `context.supported_obligations` that it did not itself advertise. `supported_obligations` in `config.yaml` lists only `notification`, so the plugin filters the declared array down to that set before the policy runs, and the policy issues the obligation only when `notification` survives. `negotiated_obligations` echoes what survived, which is how the e2e suite observes the filter from outside the PDP.

## Test coverage

`./scripts/test-local.sh` replays the interop decision cases and additionally exercises the protocol surface those cases don't reach. Against opa-authzen-plugin 0.10:

| Area                             | Spec reference          | Assertions |
| -------------------------------- | ----------------------- | ---------: |
| Per-user decision cases (5 users) | Section 5               |         40 |
| Batch evaluations                | Section 7.1             |          5 |
| Search APIs                      | Section 8               |         14 |
| Search pagination                | Section 8.5             |          3 |
| Evaluation semantics             | Section 7.1.2.1         |          3 |
| Decision context and obligations | Section 5.5.1 + profile |          9 |
| PDP metadata and transport       | Sections 9, 10, 11.7    |          9 |
| **Total**                        |                         |     **83** |

Rego unit tests (`make rego-test`) cover the same policy rules without a running PDP: 40 tests.

## References

- [OpenID AuthZEN Working Group](https://openid.net/wg/authzen/)
- [Authorization API 1.0 spec](https://openid.github.io/authzen/)
- [AuthZEN Obligations Profile 1.0](https://openid.github.io/authzen/authzen-obligations-profile-1_0.html)
- [AuthZEN Interop Results](https://authzen-interop.net)
- [openid/authzen](https://github.com/openid/authzen)
- [opa-authzen-plugin](https://github.com/kanywst/opa-authzen-plugin)
