# Release Process

This document describes the process for releasing new versions of opa-authzen-plugin.

## Version Scheme

This project currently uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html): **`vMAJOR.MINOR.PATCH`**

> [!NOTE]
> If this project is donated to the `open-policy-agent` org, the version scheme will switch to **`<opa_version>-authzen-<N>`** to match the convention used by [opa-envoy-plugin](https://github.com/open-policy-agent/opa-envoy-plugin) (e.g., `1.15.1-authzen-1`).

## Release Checklist

1. **Verify tests pass**

   ```bash
   make clean build test
   go test -v -race ./...
   ```

2. **Run linting**

   ```bash
   make fmt vet lint
   ```

3. **Check dependencies**

   ```bash
   go list -m all
   make licenses
   ```

4. **Update CHANGELOG.md**

   - Move "Unreleased" section content to new version heading
   - Follow [Keep a Changelog](https://keepachangelog.com/) format
   - Include OPA version compatibility note

5. **Dry-run the release locally (optional)**

   Runs the same GoReleaser pipeline CI will run, into `dist/`, without publishing anything. Signing is skipped because keyless signing needs a CI OIDC token.

   ```bash
   make release
   ```

6. **Create annotated git tag**

   ```bash
   git tag -a vX.Y.Z -m "Release vX.Y.Z"
   git push origin vX.Y.Z
   ```

7. **Let the tag workflows run**

   Pushing the tag triggers two workflows. `post-tag.yaml` runs GoReleaser, which cross-compiles the binaries, generates an SPDX SBOM, writes and signs `checksums.txt`, and opens a **draft** GitHub Release with all of it attached. `publish.yaml` builds and pushes the multi-arch image to `ghcr.io/kanywst/opa-authzen-plugin` with an SBOM and provenance attestation, then signs the pushed digest.

8. **Publish the draft Release**

   - Confirm both workflows are green and every asset is attached
   - Copy the CHANGELOG entry into the release notes
   - Mark as "Latest Release" if appropriate

## Verifying a Release

Release artifacts are signed with [Sigstore](https://www.sigstore.dev/) keyless signing, so there is no long-lived key to publish or rotate. Each command below pins the signer identity to this repository's own tag workflow, which is what makes the check meaningful: a signature produced by any other workflow, repository, or laptop fails.

Binaries — verify the signature on `checksums.txt` first, then check the binary against it. The signature and its certificate travel together in `checksums.txt.sigstore.json`, a Sigstore bundle:

```bash
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/kanywst/opa-authzen-plugin/\.github/workflows/post-tag\.yaml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

sha256sum --check --ignore-missing checksums.txt
```

Container image:

```bash
cosign verify ghcr.io/kanywst/opa-authzen-plugin:X.Y.Z \
  --certificate-identity-regexp '^https://github\.com/kanywst/opa-authzen-plugin/\.github/workflows/publish\.yaml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Bill of materials — the image carries a BuildKit-generated SPDX SBOM and a SLSA provenance attestation, and the GitHub Release carries an SBOM of the source module as `opa_authzen_sbom.spdx.json`:

```bash
docker buildx imagetools inspect ghcr.io/kanywst/opa-authzen-plugin:X.Y.Z --format '{{ json .SBOM }}'
```

## Pre-Release Checks

### Backward Compatibility

- Run tests on the minimum supported OPA version specified in `go.mod`
- Verify example policies still work
- Check for API-breaking changes

### Dependency Updates

- Run `go get -u` to check for available updates
- Review security advisories: `go list -u -m all`
- Update `go.mod` and `go.sum` if updates are important

### Documentation

- README.md reflects current feature set
- Example policies are up-to-date
- API documentation is accurate

## Troubleshooting

### Docker image build fails

```bash
make docker-build  # Uses git tags for versioning
# Ensure git tags are properly set
git describe --tags --always --dirty
```

### Release artifacts not generated

```bash
make clean release
# GoReleaser writes everything under dist/
ls -la dist/
```

To check the configuration itself without building:

```bash
go run github.com/goreleaser/goreleaser/v2@$(make -s print-goreleaser-version) check
```

## Support & Maintenance

- Monitor for security issues in dependencies via GitHub's Dependabot
- Respond to issues and PRs in a timely manner
- Release patch versions for critical bugs immediately
- Plan minor versions in coordination with OPA releases
