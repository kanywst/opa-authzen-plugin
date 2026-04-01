package plugin

import (
	"github.com/kanywst/opa-authzen-plugin/internal"
	"github.com/open-policy-agent/opa/v1/plugins"
)

// Factory defines the interface OPA uses to instantiate the plugin.
type Factory struct{}

// PluginName is the name to register with the OPA plugin manager.
const PluginName = internal.PluginName

// New returns the object initialized with a valid plugin configuration.
func (Factory) New(m *plugins.Manager, config any) plugins.Plugin {
	return internal.New(m, config.(*internal.Config))
}

// Validate returns a valid configuration to instantiate the plugin.
func (Factory) Validate(m *plugins.Manager, config []byte) (any, error) {
	return internal.Validate(m, config)
}
