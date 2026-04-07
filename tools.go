// Package main provides tooling dependencies for opa-authzen-plugin.
//go:build tools
// +build tools

package main

import (
	_ "github.com/golangci/golangci-lint/cmd/golangci-lint"
	_ "github.com/google/go-licenses/cmd/go-licenses"
)
