package managementasset

import _ "embed"

//go:embed management.html
var embeddedHTML []byte

// EmbeddedHTML returns the built-in management control panel HTML.
func EmbeddedHTML() []byte {
	return embeddedHTML
}
