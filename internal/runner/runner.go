package runner

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/akeyless-community/buildkite-akeyless-plugin/internal/config"
	cloudid "github.com/akeylesslabs/akeyless-go-cloud-id"
	"github.com/akeylesslabs/akeyless-go/v5"
)

const (
	kindEnv         = "env"
	kindEnvironment = "environment"
	kindSSH1        = "private_ssh_key"
	kindSSH2        = "id_rsa_github"
	kindGitCreds    = "git-credentials"
)

type secretClass int

const (
	classStatic secretClass = iota
	classDynamic
	classRotated
)

type discovered struct {
	fullPath string
	kind     string
	class    secretClass
}

type listedItem struct {
	fullPath string
	itemType string
}

// Sync downloads configured secrets and writes a state directory consumable by the Bash hook.
func Sync(ctx context.Context, stateDir string) error {
	st, err := config.LoadSettings()
	if err != nil {
		return err
	}
	pipeline := strings.TrimSpace(os.Getenv("BUILDKITE_PIPELINE_SLUG"))
	if pipeline == "" {
		return fmt.Errorf("BUILDKITE_PIPELINE_SLUG is not set")
	}

	api, err := newClient(st.Gateway)
	if err != nil {
		return err
	}

	token, err := authenticate(ctx, api, st.Auth, st.Debug)
	if err != nil {
		return err
	}

	folders := config.ResolveFolderPaths(st.BasePath, st.Prefix, pipeline)
	if st.Debug {
		fmt.Fprintf(os.Stderr, "~~~ :gear: akeyless folders: %v\n", folders)
	}

	allowed := map[string]struct{}{
		kindEnv:         {},
		kindEnvironment: {},
		kindSSH1:        {},
		kindSSH2:        {},
		kindGitCreds:    {},
	}
	if st.CustomSecret != "" {
		allowed[st.CustomSecret] = struct{}{}
	}

	listTypes := listTypesForSettings(st)
	if st.Debug {
		fmt.Fprintf(os.Stderr, "~~~ list-items types: %v\n", listTypes)
	}

	var jobs []discovered
	for _, folder := range folders {
		items, lerr := listItemsInFolder(ctx, api, token, folder, listTypes, st.Debug)
		if lerr != nil {
			if st.Debug {
				fmt.Fprintf(os.Stderr, "~~~ :warning: list-items at %q: %v (skipping)\n", folder, lerr)
			}
			continue
		}
		for _, it := range items {
			base := path.Base(it.fullPath)
			if _, ok := allowed[base]; !ok {
				continue
			}
			cls := classFromItemType(it.itemType)
			jobs = append(jobs, discovered{fullPath: it.fullPath, kind: base, class: cls})
		}
	}

	sort.Slice(jobs, func(i, j int) bool { return jobs[i].fullPath < jobs[j].fullPath })

	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}

	envPath := filepath.Join(stateDir, "env.sh")
	envFile, err := os.OpenFile(envPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer envFile.Close()

	sshListPath := filepath.Join(stateDir, "ssh-keys.list")
	sshList, err := os.OpenFile(sshListPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer sshList.Close()

	var gitSecretPath string
	sshSerial := 0

	for _, job := range jobs {
		raw, derr := fetchSecretPayload(ctx, api, token, job, st)
		if derr != nil {
			return fmt.Errorf("get secret %q (%v): %w", job.fullPath, job.class, derr)
		}
		switch job.kind {
		case kindEnv, kindEnvironment:
			lines, perr := envExports(raw)
			if perr != nil {
				return fmt.Errorf("parse env secret %q: %w", job.fullPath, perr)
			}
			for _, line := range lines {
				if _, err := fmt.Fprintln(envFile, line); err != nil {
					return err
				}
			}
		case kindSSH1, kindSSH2:
			pem, perr := sshPEM(raw)
			if perr != nil {
				return fmt.Errorf("ssh secret %q: %w", job.fullPath, perr)
			}
			sshSerial++
			keyPath := filepath.Join(stateDir, fmt.Sprintf("ssh-%d-%s", sshSerial, filepath.Base(job.fullPath)))
			if err := os.WriteFile(keyPath, []byte(pem), 0o600); err != nil {
				return err
			}
			if _, err := fmt.Fprintln(sshList, keyPath); err != nil {
				return err
			}
		case kindGitCreds:
			if job.class != classStatic {
				return fmt.Errorf("git-credentials must be a static secret (got %q)", job.fullPath)
			}
			gitSecretPath = job.fullPath
		default:
			if st.CustomSecret != "" && job.kind == st.CustomSecret {
				lines, perr := envExports(raw)
				if perr != nil {
					return fmt.Errorf("parse env secret %q: %w", job.fullPath, perr)
				}
				for _, line := range lines {
					if _, err := fmt.Fprintln(envFile, line); err != nil {
						return err
					}
				}
			}
		}
	}

	exportsPath := filepath.Join(stateDir, "exports.sh")
	var b strings.Builder
	fmt.Fprintf(&b, "export AKEYLESS_TOKEN=%s\n", bashSingleQuote(token))
	fmt.Fprintf(&b, "export AKEYLESS_GATEWAY_URL=%s\n", bashSingleQuote(st.Gateway))
	if gitSecretPath != "" {
		fmt.Fprintf(&b, "export AKEYLESS_GIT_CREDENTIAL_SECRET=%s\n", bashSingleQuote(gitSecretPath))
	}
	if err := os.WriteFile(exportsPath, []byte(b.String()), 0o600); err != nil {
		return err
	}

	return nil
}

// GitCredential implements git's credential helper protocol (get) for URLs stored in a static secret.
func GitCredential(ctx context.Context, secretPath string) error {
	st, err := config.LoadSettings()
	if err != nil {
		return err
	}
	if tok := strings.TrimSpace(os.Getenv("AKEYLESS_TOKEN")); tok != "" {
		api, cerr := newClient(st.Gateway)
		if cerr != nil {
			return cerr
		}
		raw, gerr := getStaticSecretString(ctx, api, tok, secretPath)
		if gerr != nil {
			return gerr
		}
		return emitGitCredentials(raw, st.Debug)
	}

	api, err := newClient(st.Gateway)
	if err != nil {
		return err
	}
	token, err := authenticate(ctx, api, st.Auth, st.Debug)
	if err != nil {
		return err
	}
	raw, err := getStaticSecretString(ctx, api, token, secretPath)
	if err != nil {
		return err
	}
	return emitGitCredentials(raw, st.Debug)
}

func listTypesForSettings(st config.Settings) []string {
	types := []string{"static-secret"}
	if st.IncludeDynamicSecrets {
		types = append(types, "dynamic-secret")
	}
	if st.IncludeRotatedSecrets {
		types = append(types, "rotated-secret")
	}
	return types
}

func classFromItemType(itemType string) secretClass {
	t := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(itemType), "_", "-"))
	switch t {
	case "dynamic-secret":
		return classDynamic
	case "rotated-secret":
		return classRotated
	default:
		return classStatic
	}
}

func listItemsInFolder(ctx context.Context, api *akeyless.V2ApiService, token, folder string, typeFilter []string, debug bool) ([]listedItem, error) {
	folder = strings.TrimSpace(folder)
	if folder == "" {
		return nil, nil
	}
	if !strings.HasPrefix(folder, "/") {
		folder = "/" + folder
	}
	var outItems []listedItem
	pageToken := ""
	for {
		li := akeyless.NewListItems()
		li.SetToken(token)
		li.SetPath(folder)
		li.SetCurrentFolder(true)
		if len(typeFilter) > 0 {
			li.SetType(typeFilter)
		}
		if pageToken != "" {
			li.SetPaginationToken(pageToken)
		}
		out, _, err := api.ListItems(ctx).Body(*li).Execute()
		if err != nil {
			// Some tenants may not accept rotated-secret in a multi-type filter; fall back per type.
			if len(typeFilter) > 1 {
				return listItemsPerType(ctx, api, token, folder, typeFilter, debug)
			}
			return nil, err
		}
		if out == nil {
			break
		}
		for _, it := range out.GetItems() {
			if it.GetItemName() == "" {
				continue
			}
			outItems = append(outItems, listedItem{fullPath: it.GetItemName(), itemType: it.GetItemType()})
		}
		if !out.GetHasNext() {
			break
		}
		np := out.GetNextPage()
		if np == "" {
			break
		}
		pageToken = np
	}
	if debug {
		fmt.Fprintf(os.Stderr, "~~~ listed %d items under %q (types %v)\n", len(outItems), folder, typeFilter)
	}
	return outItems, nil
}

func listItemsPerType(ctx context.Context, api *akeyless.V2ApiService, token, folder string, types []string, debug bool) ([]listedItem, error) {
	seen := make(map[string]listedItem)
	for _, t := range types {
		batch, err := listItemsInFolder(ctx, api, token, folder, []string{t}, debug)
		if err != nil {
			if debug {
				fmt.Fprintf(os.Stderr, "~~~ :warning: list-items type %q at %q: %v\n", t, folder, err)
			}
			continue
		}
		for _, it := range batch {
			seen[it.fullPath] = it
		}
	}
	var all []listedItem
	for _, it := range seen {
		all = append(all, it)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].fullPath < all[j].fullPath })
	return all, nil
}

func fetchSecretPayload(ctx context.Context, api *akeyless.V2ApiService, token string, job discovered, st config.Settings) (string, error) {
	cls := job.class
	if job.kind == kindGitCreds {
		cls = classStatic
	}
	switch cls {
	case classDynamic:
		return getDynamicSecretString(ctx, api, token, job.fullPath, st)
	case classRotated:
		return getRotatedSecretString(ctx, api, token, job.fullPath, st)
	default:
		return getStaticSecretString(ctx, api, token, job.fullPath)
	}
}

func newClient(gatewayURL string) (*akeyless.V2ApiService, error) {
	gatewayURL = strings.TrimSpace(gatewayURL)
	if gatewayURL == "" {
		return nil, fmt.Errorf("gateway URL is empty")
	}
	cfg := akeyless.NewConfiguration()
	cfg.Servers = akeyless.ServerConfigurations{
		{URL: gatewayURL},
	}
	return akeyless.NewAPIClient(cfg).V2Api, nil
}

func authenticate(ctx context.Context, api *akeyless.V2ApiService, a config.Auth, debug bool) (string, error) {
	body := akeyless.NewAuth()
	switch a.Method {
	case "access_key":
		body.SetAccessType("access_key")
		body.SetAccessId(a.AccessID)
		key, err := a.EnvValue(a.SecretEnv)
		if err != nil {
			return "", err
		}
		body.SetAccessKey(key)
	case "aws_iam":
		cid, err := cloudid.GetCloudId()
		if err != nil {
			return "", fmt.Errorf("aws cloud id: %w", err)
		}
		body.SetAccessType("aws_iam")
		body.SetAccessId(a.AccessID)
		body.SetCloudId(cid)
	case "jwt":
		jwtVal, err := a.EnvValue(a.JWTEnv)
		if err != nil {
			return "", err
		}
		at := a.AccessTypeOverride
		if at == "" {
			at = "jwt"
		}
		body.SetAccessType(at)
		body.SetAccessId(a.AccessID)
		body.SetJwt(jwtVal)
	default:
		return "", fmt.Errorf("unsupported auth method %q", a.Method)
	}

	out, _, err := api.Auth(ctx).Body(*body).Execute()
	if err != nil {
		return "", fmt.Errorf("auth: %w", err)
	}
	if out == nil || out.GetToken() == "" {
		return "", fmt.Errorf("auth returned empty token")
	}
	if debug {
		fmt.Fprintln(os.Stderr, "~~~ :white_check_mark: authenticated to Akeyless")
	}
	return out.GetToken(), nil
}

func getStaticSecretString(ctx context.Context, api *akeyless.V2ApiService, token, fullPath string) (string, error) {
	gsv := akeyless.NewGetSecretValue([]string{fullPath})
	gsv.SetToken(token)
	resp, _, err := api.GetSecretValue(ctx).Body(*gsv).Execute()
	if err != nil {
		return "", err
	}
	if resp == nil {
		return "", fmt.Errorf("empty response for %q", fullPath)
	}
	if v, ok := resp[fullPath]; ok {
		return stringifyValue(v)
	}
	for _, v := range resp {
		s, err := stringifyValue(v)
		if err == nil && strings.TrimSpace(s) != "" {
			return s, nil
		}
	}
	return "", fmt.Errorf("no value for %q in response", fullPath)
}

func getDynamicSecretString(ctx context.Context, api *akeyless.V2ApiService, token, fullPath string, st config.Settings) (string, error) {
	body := akeyless.NewGetDynamicSecretValue(fullPath)
	body.SetToken(token)
	if st.DynamicSecretTimeout > 0 {
		body.SetTimeout(st.DynamicSecretTimeout)
	}
	if len(st.DynamicSecretArgs) > 0 {
		body.SetArgs(st.DynamicSecretArgs)
	}
	resp, _, err := api.GetDynamicSecretValue(ctx).Body(*body).Execute()
	if err != nil {
		return "", err
	}
	return mapToJSONString(resp)
}

func getRotatedSecretString(ctx context.Context, api *akeyless.V2ApiService, token, fullPath string, st config.Settings) (string, error) {
	body := akeyless.NewGetRotatedSecretValue(fullPath)
	body.SetToken(token)
	if h := strings.TrimSpace(st.RotatedSecretHost); h != "" {
		body.SetHost(h)
	}
	resp, _, err := api.GetRotatedSecretValue(ctx).Body(*body).Execute()
	if err != nil {
		return "", err
	}
	return mapToJSONString(resp)
}

func mapToJSONString(resp map[string]interface{}) (string, error) {
	if resp == nil {
		return "", fmt.Errorf("empty API response")
	}
	b, err := json.Marshal(resp)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func stringifyValue(v interface{}) (string, error) {
	switch t := v.(type) {
	case string:
		return t, nil
	case fmt.Stringer:
		return t.String(), nil
	case nil:
		return "", fmt.Errorf("nil value")
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
}

func envExports(raw string) ([]string, error) {
	raw = strings.TrimSpace(maybeDecodeBase64(raw))
	if raw == "" {
		return nil, nil
	}
	if strings.HasPrefix(strings.TrimSpace(raw), "{") {
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &obj); err == nil {
			return flattenJSONExports(obj, "")
		}
	}
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		idx := strings.IndexByte(line, '=')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if !validEnvKey(key) {
			continue
		}
		lines = append(lines, fmt.Sprintf("export %s=%s", key, strconv.Quote(val)))
	}
	return lines, nil
}

func flattenJSONExports(m map[string]interface{}, prefix string) ([]string, error) {
	var out []string
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := m[k]
		name := k
		if prefix != "" {
			name = prefix + "_" + k
		}
		name = sanitizeKey(name)
		switch t := v.(type) {
		case map[string]interface{}:
			inner, err := flattenJSONExports(t, name)
			if err != nil {
				return nil, err
			}
			out = append(out, inner...)
		case []interface{}:
			b, err := json.Marshal(t)
			if err != nil {
				return nil, err
			}
			out = append(out, fmt.Sprintf("export %s=%s", name, strconv.Quote(string(b))))
		default:
			out = append(out, fmt.Sprintf("export %s=%s", name, strconv.Quote(fmt.Sprint(t))))
		}
	}
	return out, nil
}

func sshPEM(raw string) (string, error) {
	raw = strings.TrimSpace(maybeDecodeBase64(raw))
	if raw == "" {
		return "", fmt.Errorf("empty ssh secret")
	}
	if strings.HasPrefix(strings.TrimSpace(raw), "{") {
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &m); err == nil {
			if sk, ok := m["ssh_key"].(string); ok && strings.TrimSpace(sk) != "" {
				return sk, nil
			}
			// Dynamic / rotated payloads often use "private_key" or similar.
			for _, key := range []string{"private_key", "privateKey", "pem", "key"} {
				if s, ok := m[key].(string); ok && strings.Contains(s, "BEGIN") {
					return s, nil
				}
			}
		}
	}
	if !strings.Contains(raw, "BEGIN") {
		return "", fmt.Errorf("ssh secret must contain PEM, JSON with ssh_key, or a dynamic payload with a private key field")
	}
	return raw, nil
}

func emitGitCredentials(raw string, debug bool) error {
	raw = strings.TrimSpace(maybeDecodeBase64(raw))
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := url.Parse(line)
		if err != nil {
			return fmt.Errorf("parse credential url: %w", err)
		}
		user := ""
		pass := ""
		if u.User != nil {
			user = u.User.Username()
			pass, _ = u.User.Password()
		}
		host := u.Hostname()
		port := u.Port()
		if host == "" {
			return fmt.Errorf("credential url missing host: %q", line)
		}
		hostOut := host
		if port != "" {
			hostOut = host + ":" + port
		}
		if debug {
			fmt.Fprintf(os.Stderr, "~~~ git credential for host %s\n", hostOut)
		}
		fmt.Printf("protocol=%s\n", u.Scheme)
		fmt.Printf("host=%s\n", hostOut)
		fmt.Printf("username=%s\n", user)
		fmt.Printf("password=%s\n", pass)
	}
	return nil
}

func maybeDecodeBase64(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if strings.Contains(s, "\n") || strings.Contains(s, "=") && !strings.Contains(s, "://") {
		if b, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(s, "\n", "")); err == nil && len(b) > 0 && printableRatio(b) > 0.85 {
			return string(b)
		}
		return s
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) == 0 {
		return s
	}
	if printableRatio(b) > 0.85 {
		return string(b)
	}
	return s
}

func printableRatio(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	n := 0
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 32 && c < 127) {
			n++
		}
	}
	return float64(n) / float64(len(b))
}

func validEnvKey(k string) bool {
	if k == "" {
		return false
	}
	for i, r := range k {
		if i == 0 && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && r != '_' {
			return false
		}
		if i > 0 && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

func sanitizeKey(k string) string {
	var b strings.Builder
	for i, r := range k {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '_':
			b.WriteRune(r)
		default:
			if i > 0 {
				b.WriteByte('_')
			}
		}
	}
	s := b.String()
	s = strings.Trim(s, "_")
	if s == "" {
		return "KEY"
	}
	r0, _ := utf8.DecodeRuneInString(s)
	if !((r0 >= 'A' && r0 <= 'Z') || (r0 >= 'a' && r0 <= 'z') || r0 == '_') {
		s = "K_" + s
	}
	return s
}

func bashSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
