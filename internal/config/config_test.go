package config

import (
	"testing"
)

func TestResolveFolderPaths(t *testing.T) {
	p := ResolveFolderPaths("/buildkite", "acme", "svc-api")
	if len(p) != 2 || p[0] != "/buildkite/acme/svc-api" || p[1] != "/buildkite" {
		t.Fatalf("unexpected paths: %v", p)
	}
}

func TestLoadSettings_AccessKey(t *testing.T) {
	t.Setenv(PluginEnvPrefix+"_AUTH_METHOD", "access_key")
	t.Setenv(PluginEnvPrefix+"_AUTH_ACCESS_ID", "p-123")
	t.Setenv(PluginEnvPrefix+"_AUTH_SECRET_ENV", "MYKEY")
	t.Setenv("MYKEY", "secret")
	s, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if s.Gateway != "https://api.akeyless.io" || s.BasePath != "/buildkite" || s.Prefix != "" || s.CustomSecret != "" || s.Debug {
		t.Fatalf("defaults wrong: %+v", s)
	}
	if !s.IncludeDynamicSecrets || !s.IncludeRotatedSecrets {
		t.Fatalf("expected dynamic and rotated included by default")
	}
	if s.Auth.Method != "access_key" || s.Auth.AccessID != "p-123" || s.Auth.SecretEnv != "MYKEY" {
		t.Fatalf("auth: %+v", s.Auth)
	}
}

func TestLoadSettings_DisableDynamic(t *testing.T) {
	t.Setenv(PluginEnvPrefix+"_AUTH_METHOD", "access_key")
	t.Setenv(PluginEnvPrefix+"_AUTH_ACCESS_ID", "p-123")
	t.Setenv(PluginEnvPrefix+"_AUTH_SECRET_ENV", "MYKEY")
	t.Setenv("MYKEY", "secret")
	t.Setenv(PluginEnvPrefix+"_INCLUDE_DYNAMIC_SECRETS", "false")
	s, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if s.IncludeDynamicSecrets {
		t.Fatal("expected dynamic disabled")
	}
	if !s.IncludeRotatedSecrets {
		t.Fatal("expected rotated still default true")
	}
}

func TestLoadSettings_MissingMethod(t *testing.T) {
	t.Setenv(PluginEnvPrefix+"_AUTH_METHOD", "")
	_, err := LoadSettings()
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestLoadSettings_DynamicArgsIndexed(t *testing.T) {
	t.Setenv(PluginEnvPrefix+"_AUTH_METHOD", "access_key")
	t.Setenv(PluginEnvPrefix+"_AUTH_ACCESS_ID", "p-1")
	t.Setenv(PluginEnvPrefix+"_AUTH_SECRET_ENV", "K")
	t.Setenv("K", "x")
	t.Setenv(PluginEnvPrefix+"_DYNAMIC_SECRET_ARGS_0", "a=1")
	t.Setenv(PluginEnvPrefix+"_DYNAMIC_SECRET_ARGS_1", "b=2")
	s, err := LoadSettings()
	if err != nil {
		t.Fatal(err)
	}
	if len(s.DynamicSecretArgs) != 2 || s.DynamicSecretArgs[0] != "a=1" || s.DynamicSecretArgs[1] != "b=2" {
		t.Fatalf("args: %#v", s.DynamicSecretArgs)
	}
}
