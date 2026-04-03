# opa-authzen-plugin

This repository contains an extended version of OPA (**OPA-AuthZEN**) that implements the [OpenID AuthZEN Authorization API 1.0](https://openid.net/specs/authorization-api-1_0.html).

## Issue Management

Use [GitHub Issues](https://github.com/kanywst/opa-authzen-plugin/issues) to request features or file bugs.

## Overview

OPA-AuthZEN extends OPA with routes that implement the AuthZEN [Access Evaluation API](https://openid.net/specs/authorization-api-1_0.html#section-6). You can use this version of OPA as a standard AuthZEN-compatible PDP (Policy Decision Point) without a separate proxy process.

The plugin registers AuthZEN endpoints directly on OPA's own HTTP server (`:8181`) using OPA's `ExtraRoute` extension point. This means AuthZEN routes get OPA's built-in Prometheus metrics, OpenTelemetry tracing, and server authorization automatically — no separate port or listener required.

## Quick Start

1. Build the plugin.

    ```bash
    make build
    ```

2. Create a policy file `policy.rego`:

    ```rego
    package authzen

    default allow = false

    allow if input.subject.properties.role == "admin"

    allow if {
        input.action.name == "read"
        input.subject.id != ""
    }
    ```

3. Create a config file `config.yaml`:

    ```yaml
    plugins:
      authzen:
        path: "authzen"
        decision: "allow"
    ```

4. Run the plugin.

    ```bash
    ./opa-authzen-plugin run --server --config-file config.yaml policy.rego
    ```

    This starts OPA on `:8181` with the AuthZEN endpoints registered on the same server.

5. Send an AuthZEN evaluation request.

    ```bash
    curl -s -X POST http://localhost:8181/access/v1/evaluation \
      -H "Content-Type: application/json" \
      -d '{
        "subject": {"type": "user", "id": "alice", "properties": {"role": "admin"}},
        "resource": {"type": "document", "id": "doc-123"},
        "action": {"name": "delete"}
      }'
    ```

    The response should be:

    ```json
    {"decision":true}
    ```

6. Check the well-known metadata endpoint.

    ```bash
    curl -s http://localhost:8181/.well-known/authzen-configuration | jq .
    ```

## Docker

```bash
make docker-build
make docker-run
```

## Configuration

The plugin is configured under the `plugins.authzen` key in the OPA config file:

| Key        | Type   | Default   | Description                                                     |
| ---------- | ------ | --------- | --------------------------------------------------------------- |
| `path`     | string | `authzen` | OPA package path to query                                       |
| `decision` | string | `allow`   | Rule name within the package that produces the boolean decision |

## License

Apache License 2.0. See [LICENSE](./LICENSE).
