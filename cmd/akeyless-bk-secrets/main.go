package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/akeyless-community/buildkite-akeyless-plugin/internal/runner"
)

func main() {
	ctx := context.Background()
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "sync":
		dir := ""
		if len(os.Args) >= 3 {
			dir = strings.TrimSpace(os.Args[2])
		}
		if dir == "" {
			fmt.Fprintln(os.Stderr, "usage: akeyless-bk-secrets sync <state-dir>")
			os.Exit(2)
		}
		if err := runner.Sync(ctx, dir); err != nil {
			fmt.Fprintf(os.Stderr, "+++ :warning: akeyless-bk-secrets sync: %v\n", err)
			os.Exit(1)
		}
	case "git-credential":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: akeyless-bk-secrets git-credential <full-secret-path>")
			os.Exit(2)
		}
		path := strings.TrimSpace(os.Args[2])
		if err := runner.GitCredential(ctx, path); err != nil {
			fmt.Fprintf(os.Stderr, "git-credential: %v\n", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "akeyless-bk-secrets — Buildkite helper for Akeyless static secrets")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "  akeyless-bk-secrets sync <state-dir>")
	fmt.Fprintln(os.Stderr, "  akeyless-bk-secrets git-credential <full-secret-path>")
}
