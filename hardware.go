package runtime

import hardwareid "github.com/camelliavv/license-runtime/hardwareid"

func CurrentHardwareID() (string, error) { return hardwareid.Current() }
