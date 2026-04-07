# Contributing to opa-authzen-plugin

Thank you for your interest in contributing to opa-authzen-plugin! This guide will help you get started.

## Development Setup

### Prerequisites

- Go 1.26.1 or later (see `.go-version`)
- GNU Make
- Git

### Building

```bash
make build        # Build the binary
make test         # Run all tests
make fmt          # Format code
make vet          # Run static analysis
```

### Testing

```bash
# Run all tests
make test

# Run tests with race detector
go test -v -race ./...

# Run a specific test
go test -v -run TestName ./internal
```

## Contributing Process

### 1. Fork and Clone

```bash
git clone https://github.com/kanywst/opa-authzen-plugin.git
cd opa-authzen-plugin
```

### 2. Create a Feature Branch

```bash
git checkout -b fix/your-fix
# or
git checkout -b feat/your-feature
```

### 3. Make Your Changes

- Keep changes focused on a single issue or feature
- Write clear commit messages
- Add or update tests as appropriate

### 4. Commit with DCO Sign-off

All commits must be signed off with the Developer Certificate of Origin (DCO):

```bash
git commit -s -m "Brief description of changes"
```

The `-s` flag adds a `Signed-off-by:` line to your commit message. This confirms that you have the right to contribute the code under the Apache 2.0 license.

### 5. Push and Create a Pull Request

```bash
git push origin fix/your-fix
```

Then create a PR on GitHub. Include:
- A clear description of what your PR does
- References to any related issues
- Test coverage for new functionality

## Code Style

- Follow [effective Go](https://golang.org/doc/effective_go)
- Format code with `go fmt`
- Run `go vet` before submitting
- Keep lines under 100 characters where reasonable

## Testing

- Write table-driven tests (see `internal/internal_test.go` for examples)
- All tests must pass: `make test`
- Run tests with race detector for concurrency validation: `go test -v -race ./...`

## Documentation

- Update README.md for user-facing changes
- Add comments to non-obvious code
- Update .github/copilot-instructions.md if architectural patterns change

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
