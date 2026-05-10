.PHONY: build test fmt

build:
	CGO_ENABLED=0 go build -buildvcs=false -o bin/akeyless-bk-secrets ./cmd/akeyless-bk-secrets
	chmod +x git-credential-akeyless-secrets

fmt:
	go fmt ./...

test:
	go test -buildvcs=false ./...
