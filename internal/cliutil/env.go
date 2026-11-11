package cliutil

import (
	"fmt"
	"os"
	"strings"
)

// EnvVar is an explicitly selected sandbox environment value. An empty value
// is distinct from an unset host variable, which --env NAME refuses.
type EnvVar struct{ Name, Value string }

func parseEnv(raw string) (EnvVar, error) {
	name, value, literal := strings.Cut(raw, "=")
	if !validEnvName(name) {
		return EnvVar{}, fmt.Errorf("argument --env: invalid variable name %q (expected [A-Za-z_][A-Za-z0-9_]*)", name)
	}
	if !literal {
		var ok bool
		value, ok = os.LookupEnv(name)
		if !ok {
			return EnvVar{}, fmt.Errorf("argument --env: host variable %q is not set (use %s= for an empty value)", name, name)
		}
	}
	if strings.ContainsRune(value, 0) {
		return EnvVar{}, fmt.Errorf("argument --env: value for %q contains a NUL byte", name)
	}
	return EnvVar{Name: name, Value: value}, nil
}

func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}
