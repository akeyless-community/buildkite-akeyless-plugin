package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// PluginEnvPrefix is the environment variable prefix Buildkite sets for this repository
// (GitHub: akeyless-community/buildkite-akeyless-plugin → buildkite-akeyless-plugin → BUILDKITE_PLUGIN_BUILDKITE_AKEYLESS_PLUGIN).
// https://buildkite.com/docs/pipelines/integrations/plugins/writing
const PluginEnvPrefix = "BUILDKITE_PLUGIN_BUILDKITE_AKEYLESS_PLUGIN"

func pluginEnv(suffix string) string {
	return PluginEnvPrefix + "_" + suffix
}

// Settings holds plugin configuration from Buildkite environment variables.
type Settings struct {
	Gateway      string
	BasePath     string
	Prefix       string
	CustomSecret string
	Debug        bool

	IncludeDynamicSecrets bool
	IncludeRotatedSecrets bool

	DynamicSecretTimeout int64
	DynamicSecretArgs    []string

	RotatedSecretHost string

	Auth Auth
}

// LoadSettings reads plugin configuration from the agent environment.
func LoadSettings() (Settings, error) {
	var s Settings
	s.Gateway = strings.TrimSpace(os.Getenv(pluginEnv("GATEWAY")))
	if s.Gateway == "" {
		s.Gateway = "https://api.akeyless.io"
	}
	s.BasePath = strings.TrimSpace(os.Getenv(pluginEnv("PATH")))
	if s.BasePath == "" {
		s.BasePath = "/buildkite"
	}
	s.Prefix = strings.TrimSpace(os.Getenv(pluginEnv("PREFIX")))
	s.CustomSecret = strings.TrimSpace(os.Getenv(pluginEnv("SECRET")))
	dbg := strings.TrimSpace(os.Getenv(pluginEnv("DEBUG")))
	s.Debug = dbg == "true" || dbg == "1"

	s.IncludeDynamicSecrets = parseBoolDefaultTrue(pluginEnv("INCLUDE_DYNAMIC_SECRETS"))
	s.IncludeRotatedSecrets = parseBoolDefaultTrue(pluginEnv("INCLUDE_ROTATED_SECRETS"))

	if ts := strings.TrimSpace(os.Getenv(pluginEnv("DYNAMIC_SECRET_TIMEOUT"))); ts != "" {
		n, err := parsePositiveInt64(ts)
		if err != nil {
			return Settings{}, fmt.Errorf("dynamic_secret_timeout: %w", err)
		}
		s.DynamicSecretTimeout = n
	}
	s.DynamicSecretArgs = loadDynamicSecretArgs()
	s.RotatedSecretHost = strings.TrimSpace(os.Getenv(pluginEnv("ROTATED_SECRET_HOST")))

	s.Auth.Method = strings.TrimSpace(os.Getenv(pluginEnv("AUTH_METHOD")))
	if s.Auth.Method == "" {
		return Settings{}, fmt.Errorf("auth.method is required")
	}
	s.Auth.AccessID = strings.TrimSpace(os.Getenv(pluginEnv("AUTH_ACCESS_ID")))
	s.Auth.SecretEnv = strings.TrimSpace(os.Getenv(pluginEnv("AUTH_SECRET_ENV")))
	s.Auth.JWTEnv = strings.TrimSpace(os.Getenv(pluginEnv("AUTH_JWT_ENV")))
	s.Auth.AccessTypeOverride = strings.TrimSpace(os.Getenv(pluginEnv("AUTH_ACCESS_TYPE")))

	switch s.Auth.Method {
	case "access_key":
		if s.Auth.AccessID == "" {
			return Settings{}, fmt.Errorf("auth.access-id is required for access_key")
		}
		if s.Auth.SecretEnv == "" {
			s.Auth.SecretEnv = "AKEYLESS_ACCESS_KEY"
		}
	case "aws_iam":
		if s.Auth.AccessID == "" {
			return Settings{}, fmt.Errorf("auth.access-id is required for aws_iam")
		}
	case "jwt":
		if s.Auth.AccessID == "" {
			return Settings{}, fmt.Errorf("auth.access-id is required for jwt")
		}
		if s.Auth.JWTEnv == "" {
			s.Auth.JWTEnv = "AKEYLESS_JWT"
		}
	default:
		return Settings{}, fmt.Errorf("unsupported auth.method %q (use access_key, aws_iam, jwt)", s.Auth.Method)
	}

	return s, nil
}

func loadDynamicSecretArgs() []string {
	base := pluginEnv("DYNAMIC_SECRET_ARGS")
	var out []string
	for i := 0; i < 256; i++ {
		k := fmt.Sprintf("%s_%d", base, i)
		v := strings.TrimSpace(os.Getenv(k))
		if v == "" {
			break
		}
		out = append(out, v)
	}
	if len(out) > 0 {
		return out
	}
	raw := strings.TrimSpace(os.Getenv(base))
	if raw == "" {
		return nil
	}
	var parsed []string
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		return nil
	}
	return parsed
}

func parseBoolDefaultTrue(envKey string) bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv(envKey)))
	if v == "" {
		return true
	}
	return v != "false" && v != "0" && v != "no" && v != "off"
}

func parsePositiveInt64(s string) (int64, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("invalid positive integer %q", s)
	}
	return n, nil
}

// ResolveFolderPaths returns [pipeline-specific, org-wide] Akeyless folder paths to scan.
func ResolveFolderPaths(basePath, prefix, pipelineSlug string) []string {
	basePath = normalizePath(basePath)
	var mid string
	if prefix != "" {
		mid = joinPath(basePath, prefix)
	} else {
		mid = basePath
	}
	specific := joinPath(mid, pipelineSlug)
	return []string{specific, basePath}
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimSuffix(p, "/")
}

func joinPath(base, seg string) string {
	base = normalizePath(base)
	seg = strings.Trim(seg, "/")
	if seg == "" {
		return base
	}
	return base + "/" + seg
}

// Auth holds authentication-related plugin options.
type Auth struct {
	Method             string
	AccessID           string
	SecretEnv          string
	JWTEnv             string
	AccessTypeOverride string
}

// EnvValue returns the secret material from the named environment variable.
func (a Auth) EnvValue(envVar string) (string, error) {
	if envVar == "" {
		return "", fmt.Errorf("empty environment variable name")
	}
	v := os.Getenv(envVar)
	if v == "" {
		return "", fmt.Errorf("environment variable %q is empty or unset", envVar)
	}
	return v, nil
}
