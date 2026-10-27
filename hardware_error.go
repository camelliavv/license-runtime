package runtime

import hardwareid "github.com/camelliavv/license-runtime/hardwareid"

func hardwareIDUnavailable() error { return hardwareid.ErrUnavailable }
