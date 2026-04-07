# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in opa-authzen-plugin, please **do not** open a public issue. Instead, please email the maintainer directly:

- kanywst12@gmail.com

Please include:
- Description of the vulnerability
- Steps to reproduce (if possible)
- Potential impact
- Suggested fix (if you have one)

We will acknowledge receipt of your report within 48 hours and work with you to understand and resolve the issue.

## Supported Versions

| Version | Status | Support Until                               |
| ------- | ------ | ------------------------------------------- |
| v0.1.x  | Latest | Updates as long as no critical issues arise |

## Security Considerations

- The plugin runs as part of OPA's main process. Ensure the OPA process is run with appropriate security contexts.
- Always validate your Rego policies for security implications.
- Keep OPA and all dependencies up to date.
- Use HTTPS when communicating with the authorization API in production.

## Dependencies

We regularly update dependencies. You can check for vulnerabilities using:

```bash
go list -m all | grep -i "vulnerable"
```

Report dependency vulnerabilities to the respective maintainers.
