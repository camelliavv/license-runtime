package runtime

import hardwareid "github.com/camelliavv/license-runtime/hardwareid"

// CurrentHardwareID returns the stable identifier for the current host.
func CurrentHardwareID() (string, error) { return hardwareid.Current() }
