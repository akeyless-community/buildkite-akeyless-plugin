# Buildkite Akeyless Plugin

Load secrets from [Akeyless](https://www.akeyless.io) into Buildkite jobs: **static**, **dynamic**, and **rotated** items (see below), plus environment exports, `ssh-agent` keys, and Git HTTPS credentials.

Uses the official [Akeyless Go SDK](https://github.com/akeylesslabs/akeyless-go) (`v5`) and [akeyless-go-cloud-id](https://github.com/akeylesslabs/akeyless-go-cloud-id) for AWS IAM auth.

**Repository:** [github.com/akeyless-community/buildkite-akeyless-plugin](https://github.com/akeyless-community/buildkite-akeyless-plugin)

## Install on the agent

Build the helper once per plugin checkout (or bake into your agent image):

```bash
make build
```

## Pipeline usage

Reference the plugin by GitHub coordinates and tag:

```yaml
plugins:
  - akeyless-community/buildkite-akeyless-plugin#v1.0.0:
      auth:
        method: access_key
        access-id: "p-XXXX"
```

Buildkite exposes settings as environment variables with prefix **`BUILDKITE_PLUGIN_BUILDKITE_AKEYLESS_PLUGIN_`** (derived from the repository name). The Go code reads that prefix automatically.

## Examples

### Access key

```yaml
steps:
  - command: ./scripts/ci.sh
    plugins:
      - akeyless-community/buildkite-akeyless-plugin#v1.0.0:
          gateway: "https://api.akeyless.io"
          auth:
            method: access_key
            access-id: "p-XXXX"
            secret-env: "AKEYLESS_ACCESS_KEY"
```

Provide `AKEYLESS_ACCESS_KEY` on the agent (environment hook, secrets manager, etc.).

### AWS IAM

```yaml
steps:
  - command: ./scripts/ci.sh
    plugins:
      - akeyless-community/buildkite-akeyless-plugin#v1.0.0:
          gateway: "https://api.akeyless.io"
          auth:
            method: aws_iam
            access-id: "p-XXXX"
```

### JWT (or OIDC via `access-type`)

```yaml
steps:
  - command: ./scripts/ci.sh
    plugins:
      - akeyless-community/buildkite-akeyless-plugin#v1.0.0:
          gateway: "https://api.akeyless.io"
          auth:
            method: jwt
            access-id: "p-XXXX"
            jwt-env: "AKEYLESS_JWT"
            # access-type: "oidc"  # if your Akeyless auth method requires it
```

### Dynamic / rotated options

```yaml
steps:
  - command: ./scripts/ci.sh
    plugins:
      - akeyless-community/buildkite-akeyless-plugin#v1.0.0:
          gateway: "https://api.akeyless.io"
          include_dynamic_secrets: true
          include_rotated_secrets: true
          dynamic_secret_timeout: 60
          rotated_secret_host: "db.internal.example"
          auth:
            method: access_key
            access-id: "p-XXXX"
```

## Secret layout

Default Akeyless folder base: `/buildkite` (override with `path`). The plugin scans:

1. `/buildkite/<prefix>/<BUILDKITE_PIPELINE_SLUG>` or `/buildkite/<BUILDKITE_PIPELINE_SLUG>`
2. `/buildkite` (shared fallback)

Items are matched by the **last path segment** (static, dynamic, or rotated):

| Name | Role |
| --- | --- |
| `env` / `environment` | Env: `KEY=value` lines, JSON, or API JSON for dynamic/rotated |
| `private_ssh_key` / `id_rsa_github` | PEM or JSON with `ssh_key` / `private_key` / similar → `ssh-add` |
| `git-credentials` | **Static only** — lines like `https://user:token@host/...` for Git credential helper |
| *custom* | With `secret: myname`, an item named `myname` is loaded like `env` |

Set `include_dynamic_secrets: false` or `include_rotated_secrets: false` to limit listing.

## Configuration reference

| Key | Purpose |
| --- | --- |
| `gateway` | API base URL (default `https://api.akeyless.io`; self-hosted gateways use the URL your team documents). |
| `path` | Base folder in Akeyless (default `/buildkite`). |
| `prefix` | Optional path segment between base and pipeline slug. |
| `secret` | Optional extra item name (last segment) merged as env-style exports. |
| `debug` | Verbose logs. |
| `dump_env` | Log variables added by the plugin (avoid on shared logs). |
| `include_dynamic_secrets` | Default on; set `false` to skip dynamic secrets. |
| `include_rotated_secrets` | Default on; set `false` to skip rotated secrets. |
| `dynamic_secret_timeout` | Seconds for `get-dynamic-secret-value`. |
| `dynamic_secret_args` | String array passed to dynamic secret provisioning. |
| `rotated_secret_host` | Optional host for `get-rotated-secret-value` (linked targets). |
| `auth` | Required: `method`, `access-id`, and method-specific fields (see examples). |

## Develop

```bash
make fmt
make test
make build
```

## License

MIT — see [LICENSE](LICENSE).
