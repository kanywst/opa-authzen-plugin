package main

import (
	"os"

	"github.com/kanywst/opa-authzen-plugin/plugin"
	"github.com/open-policy-agent/opa/cmd"
	"github.com/open-policy-agent/opa/v1/runtime"
)

func main() {
	runtime.RegisterPlugin(plugin.PluginName, plugin.Factory{})

	if err := cmd.RootCommand.Execute(); err != nil {
		os.Exit(1)
	}
}
