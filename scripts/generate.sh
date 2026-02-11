#!/usr/bin/env bash
set -euo pipefail

go run ./cmd/specsync
mkdir -p client
go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.4.1 --config oapi-codegen.yaml specs/chatwoot.openapi.json
