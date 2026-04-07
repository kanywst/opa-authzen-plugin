# Maintainers

This page lists the maintainers of opa-authzen-plugin and their areas of responsibility.

## Maintainers

| GitHub                                 | Email               |
| -------------------------------------- | ------------------- |
| [@kanywst](https://github.com/kanywst) | kanywst12@gmail.com |

## Contribution Process

When contributing to opa-authzen-plugin:

1. **Small changes** (typos, documentation): Open a PR directly
2. **Feature requests**: Open an issue for discussion first
3. **Bug fixes**: Include test cases demonstrating the fix
4. **Breaking changes**: These must be discussed and approved by maintainers

All commits must include DCO sign-off (`git commit -s`). See [CONTRIBUTING.md](./CONTRIBUTING.md) for details.

## Merge Criteria

PRs will be merged when:

- ✅ All tests pass (including new tests for new functionality)
- ✅ Code follows project style (formatted with `go fmt`, no `go vet` warnings)
- ✅ Commits include DCO sign-off
- ✅ Documentation is updated as needed
- ✅ No breaking changes to the AuthZEN API

## Release Process

Releases follow semantic versioning. Version tags are in the format `v<major>.<minor>.<patch>`. See [ROADMAP.md](./_roadmap/ROADMAP.md) for the release versioning strategy.
