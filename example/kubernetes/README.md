# Kubernetes

Runs opa-authzen-plugin as a Deployment behind a ClusterIP Service, with the plugin config and policy mounted from a ConfigMap.

## Files

| File                 | Description                                                         |
| -------------------- | ------------------------------------------------------------------- |
| `kustomization.yaml` | Namespace `authzen`, image tag, and the ConfigMap generator         |
| `deployment.yaml`    | Two replicas, non-root with a read-only root filesystem             |
| `service.yaml`       | ClusterIP on port 8181                                              |
| `config.yaml`        | Plugin config (`plugins.authzen`)                                   |
| `policy.rego`        | Policy: admins can do anything, any identified subject can read     |
| `test.sh`            | Smoke test on a kind cluster                                        |

## Deploy

```bash
kubectl apply -k example/kubernetes
kubectl -n authzen rollout status deploy/opa-authzen
```

Edit `config.yaml` or `policy.rego` and apply again. The ConfigMap name carries a content hash, so the Deployment rolls to pick up the change.

## Try it

```bash
kubectl -n authzen port-forward svc/opa-authzen 8181:8181
```

```bash
curl -s -X POST http://localhost:8181/access/v1/evaluation \
  -H "Content-Type: application/json" \
  -d '{
    "subject": {"type": "user", "id": "bob"},
    "resource": {"type": "document", "id": "d1"},
    "action": {"name": "delete"}
  }'
# → {"decision":false}
```

Inside the cluster, PEPs call `http://opa-authzen.authzen.svc:8181`. The Service also exposes OPA's own REST API (`/v1/policies`, `/v1/data`) without authentication, so restrict who can reach it before using this beyond a test cluster.

## Test

```bash
./example/kubernetes/test.sh
```

Runs the example on a kind cluster with an image built from this checkout. Needs docker, kind and kubectl. The cluster is deleted afterwards unless `KEEP_CLUSTER=1` is set.

## Cleanup

```bash
kubectl delete -k example/kubernetes
```
