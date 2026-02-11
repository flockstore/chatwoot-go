.PHONY: generate test

generate:
	./scripts/generate.sh

test:
	go test ./...
