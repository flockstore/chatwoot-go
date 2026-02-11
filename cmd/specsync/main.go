package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
)

const (
	defaultSpecURL    = "https://raw.githubusercontent.com/chatwoot/chatwoot/develop/swagger/swagger.json"
	defaultCommitsAPI = "https://api.github.com/repos/chatwoot/chatwoot/commits?path=swagger/swagger.json&sha=develop&per_page=1"
	defaultOutputPath = "specs/chatwoot.openapi.json"
	defaultStatePath  = "specs/.upstream.sha"
	userAgent         = "chatwoot-go-specsync/1.0"
)

var pathParamPattern = regexp.MustCompile(`\{([^{}]+)\}`)

func main() {
	var (
		specURL    = flag.String("spec-url", defaultSpecURL, "Upstream OpenAPI 3 specification URL")
		commitsAPI = flag.String("commits-api", defaultCommitsAPI, "GitHub API URL for latest commit affecting the spec")
		outputPath = flag.String("output", defaultOutputPath, "Path to write normalized OpenAPI 3 spec JSON")
		statePath  = flag.String("state-file", defaultStatePath, "Path storing the last processed upstream commit SHA")
		force      = flag.Bool("force", false, "Regenerate even if upstream commit SHA is unchanged")
	)
	flag.Parse()

	client := &http.Client{
		Timeout: 45 * time.Second,
	}

	latestSHA, err := fetchLatestSHA(client, *commitsAPI)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not fetch latest commit SHA: %v\n", err)
	}

	if latestSHA != "" && !*force && stateIsCurrent(*statePath, latestSHA) && fileExists(*outputPath) {
		fmt.Printf("No upstream spec changes detected (sha=%s)\n", latestSHA)
		return
	}

	specBody, err := fetch(client, *specURL)
	if err != nil {
		exitf("failed to fetch upstream spec: %v", err)
	}

	doc, err := normalizeToOpenAPI3(specBody)
	if err != nil {
		exitf("failed to normalize spec to OpenAPI 3: %v", err)
	}

	if doc.Extensions == nil {
		doc.Extensions = map[string]any{}
	}
	doc.Extensions["x-chatwoot-spec-source"] = *specURL
	if latestSHA != "" {
		doc.Extensions["x-chatwoot-upstream-commit"] = latestSHA
	}
	pruned := pruneMismatchedPathParameterDefinitions(doc)
	if pruned > 0 {
		fmt.Printf("Pruned %d mismatched path parameter definitions\n", pruned)
	}
	removed := dedupePathParameterDefinitions(doc)
	if removed > 0 {
		fmt.Printf("Removed %d duplicate path parameter definitions\n", removed)
	}
	patched := patchMissingPathParameterDefinitions(doc)
	if patched > 0 {
		fmt.Printf("Patched %d missing path parameter definitions\n", patched)
	}
	normalizedEnums := normalizeEnumSchemaTypes(doc)
	if normalizedEnums > 0 {
		fmt.Printf("Normalized %d enum schema type declarations\n", normalizedEnums)
	}

	if err := writeJSON(*outputPath, doc); err != nil {
		exitf("failed writing normalized spec: %v", err)
	}
	fmt.Printf("Wrote %s\n", *outputPath)

	if latestSHA != "" {
		if err := writeText(*statePath, latestSHA+"\n"); err != nil {
			exitf("failed writing state file: %v", err)
		}
		fmt.Printf("Updated %s (sha=%s)\n", *statePath, latestSHA)
	}
}

func fetchLatestSHA(client *http.Client, commitsAPI string) (string, error) {
	body, err := fetch(client, commitsAPI)
	if err != nil {
		return "", err
	}

	var commits []struct {
		SHA string `json:"sha"`
	}
	if err := json.Unmarshal(body, &commits); err != nil {
		return "", fmt.Errorf("decode commit response: %w", err)
	}
	if len(commits) == 0 || commits[0].SHA == "" {
		return "", fmt.Errorf("empty commit list returned by upstream")
	}
	return commits[0].SHA, nil
}

func fetch(client *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	if token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); token != "" && strings.Contains(url, "api.github.com") {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("GET %s returned %d: %s", url, resp.StatusCode, strings.TrimSpace(string(data)))
	}

	return io.ReadAll(resp.Body)
}

func normalizeToOpenAPI3(specBody []byte) (*openapi3.T, error) {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(specBody, &root); err != nil {
		return nil, fmt.Errorf("spec is not valid JSON: %w", err)
	}

	if raw, ok := root["openapi"]; ok {
		var version string
		if err := json.Unmarshal(raw, &version); err == nil && strings.HasPrefix(version, "3.") {
			loader := openapi3.NewLoader()
			return loader.LoadFromData(specBody)
		}
		if err := json.Unmarshal(raw, &version); err == nil {
			return nil, fmt.Errorf("unsupported OpenAPI version %q: expected 3.x", version)
		}
	}

	return nil, fmt.Errorf("unsupported spec format: expected OpenAPI 3.x document")
}

func patchMissingPathParameterDefinitions(doc *openapi3.T) int {
	if doc == nil || doc.Paths == nil {
		return 0
	}

	patches := 0
	for path, pathItem := range doc.Paths.Map() {
		if pathItem == nil {
			continue
		}

		pathParams := extractPathParameters(path)
		if len(pathParams) == 0 {
			continue
		}

		for _, paramName := range pathParams {
			if hasPathParam(doc, pathItem.Parameters, paramName) {
				continue
			}

			ops := pathItem.Operations()
			missing := make([]*openapi3.Operation, 0, len(ops))
			hasSome := false
			for _, op := range ops {
				if op == nil {
					continue
				}
				if hasPathParam(doc, op.Parameters, paramName) {
					hasSome = true
					continue
				}
				missing = append(missing, op)
			}

			switch {
			case !hasSome:
				pathItem.Parameters = append(pathItem.Parameters, newStringPathParam(paramName))
				patches++
			default:
				for _, op := range missing {
					op.Parameters = append(op.Parameters, newStringPathParam(paramName))
					patches++
				}
			}
		}
	}
	return patches
}

func extractPathParameters(path string) []string {
	matches := pathParamPattern.FindAllStringSubmatch(path, -1)
	if len(matches) == 0 {
		return nil
	}

	out := make([]string, 0, len(matches))
	seen := make(map[string]struct{}, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		name := strings.TrimSpace(match[1])
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out
}

func hasPathParam(doc *openapi3.T, params openapi3.Parameters, name string) bool {
	for _, paramRef := range params {
		param := resolveParameterRef(doc, paramRef)
		if param == nil {
			continue
		}
		if param.In == openapi3.ParameterInPath && param.Name == name {
			return true
		}
	}
	return false
}

func resolveParameterRef(doc *openapi3.T, parameterRef *openapi3.ParameterRef) *openapi3.Parameter {
	if parameterRef == nil {
		return nil
	}
	if parameterRef.Value != nil {
		return parameterRef.Value
	}
	if parameterRef.Ref == "" || doc == nil {
		return nil
	}
	const prefix = "#/components/parameters/"
	if strings.HasPrefix(parameterRef.Ref, prefix) {
		name := strings.TrimPrefix(parameterRef.Ref, prefix)
		if ref := doc.Components.Parameters[name]; ref != nil {
			return ref.Value
		}
	}
	return nil
}

func dedupePathParameterDefinitions(doc *openapi3.T) int {
	if doc == nil || doc.Paths == nil {
		return 0
	}

	removed := 0
	for _, pathItem := range doc.Paths.Map() {
		if pathItem == nil {
			continue
		}

		pathParamNames := map[string]struct{}{}
		for _, paramRef := range pathItem.Parameters {
			param := resolveParameterRef(doc, paramRef)
			if param == nil || param.In != openapi3.ParameterInPath || param.Name == "" {
				continue
			}
			pathParamNames[param.Name] = struct{}{}
		}
		if len(pathParamNames) == 0 {
			continue
		}

		for _, op := range pathItem.Operations() {
			if op == nil {
				continue
			}
			next := make(openapi3.Parameters, 0, len(op.Parameters))
			for _, paramRef := range op.Parameters {
				param := resolveParameterRef(doc, paramRef)
				if param != nil && param.In == openapi3.ParameterInPath {
					if _, ok := pathParamNames[param.Name]; ok {
						removed++
						continue
					}
				}
				next = append(next, paramRef)
			}
			op.Parameters = next
		}
	}
	return removed
}

func pruneMismatchedPathParameterDefinitions(doc *openapi3.T) int {
	if doc == nil || doc.Paths == nil {
		return 0
	}

	removed := 0
	for path, pathItem := range doc.Paths.Map() {
		if pathItem == nil {
			continue
		}

		validPathParams := map[string]struct{}{}
		for _, name := range extractPathParameters(path) {
			validPathParams[name] = struct{}{}
		}

		nextPathParams := make(openapi3.Parameters, 0, len(pathItem.Parameters))
		for _, paramRef := range pathItem.Parameters {
			param := resolveParameterRef(doc, paramRef)
			if param != nil && param.In == openapi3.ParameterInPath {
				if _, ok := validPathParams[param.Name]; !ok {
					removed++
					continue
				}
			}
			nextPathParams = append(nextPathParams, paramRef)
		}
		pathItem.Parameters = nextPathParams

		for _, op := range pathItem.Operations() {
			if op == nil {
				continue
			}
			nextOpParams := make(openapi3.Parameters, 0, len(op.Parameters))
			for _, paramRef := range op.Parameters {
				param := resolveParameterRef(doc, paramRef)
				if param != nil && param.In == openapi3.ParameterInPath {
					if _, ok := validPathParams[param.Name]; !ok {
						removed++
						continue
					}
				}
				nextOpParams = append(nextOpParams, paramRef)
			}
			op.Parameters = nextOpParams
		}
	}
	return removed
}

func normalizeEnumSchemaTypes(doc *openapi3.T) int {
	if doc == nil {
		return 0
	}

	visited := map[*openapi3.Schema]struct{}{}
	updates := 0

	for _, schemaRef := range doc.Components.Schemas {
		updates += normalizeEnumSchemaRefTypes(schemaRef, visited)
	}
	for _, paramRef := range doc.Components.Parameters {
		if paramRef == nil || paramRef.Value == nil {
			continue
		}
		updates += normalizeEnumSchemaRefTypes(paramRef.Value.Schema, visited)
	}
	for _, requestBodyRef := range doc.Components.RequestBodies {
		if requestBodyRef == nil || requestBodyRef.Value == nil {
			continue
		}
		for _, mediaType := range requestBodyRef.Value.Content {
			if mediaType == nil {
				continue
			}
			updates += normalizeEnumSchemaRefTypes(mediaType.Schema, visited)
		}
	}
	for _, responseRef := range doc.Components.Responses {
		if responseRef == nil || responseRef.Value == nil {
			continue
		}
		for _, mediaType := range responseRef.Value.Content {
			if mediaType == nil {
				continue
			}
			updates += normalizeEnumSchemaRefTypes(mediaType.Schema, visited)
		}
	}

	for _, pathItem := range doc.Paths.Map() {
		if pathItem == nil {
			continue
		}
		for _, paramRef := range pathItem.Parameters {
			if paramRef == nil || paramRef.Value == nil {
				continue
			}
			updates += normalizeEnumSchemaRefTypes(paramRef.Value.Schema, visited)
		}
		for _, op := range pathItem.Operations() {
			if op == nil {
				continue
			}
			for _, paramRef := range op.Parameters {
				if paramRef == nil || paramRef.Value == nil {
					continue
				}
				updates += normalizeEnumSchemaRefTypes(paramRef.Value.Schema, visited)
			}
			if op.RequestBody != nil && op.RequestBody.Value != nil {
				for _, mediaType := range op.RequestBody.Value.Content {
					if mediaType == nil {
						continue
					}
					updates += normalizeEnumSchemaRefTypes(mediaType.Schema, visited)
				}
			}
			for _, responseRef := range op.Responses.Map() {
				if responseRef == nil || responseRef.Value == nil {
					continue
				}
				for _, mediaType := range responseRef.Value.Content {
					if mediaType == nil {
						continue
					}
					updates += normalizeEnumSchemaRefTypes(mediaType.Schema, visited)
				}
			}
		}
	}

	return updates
}

func normalizeEnumSchemaRefTypes(schemaRef *openapi3.SchemaRef, visited map[*openapi3.Schema]struct{}) int {
	if schemaRef == nil || schemaRef.Value == nil {
		return 0
	}
	schema := schemaRef.Value
	if _, ok := visited[schema]; ok {
		return 0
	}
	visited[schema] = struct{}{}

	updates := 0
	if normalizeEnumType(schema) {
		updates++
	}

	for _, ref := range schema.AllOf {
		updates += normalizeEnumSchemaRefTypes(ref, visited)
	}
	for _, ref := range schema.AnyOf {
		updates += normalizeEnumSchemaRefTypes(ref, visited)
	}
	for _, ref := range schema.OneOf {
		updates += normalizeEnumSchemaRefTypes(ref, visited)
	}
	updates += normalizeEnumSchemaRefTypes(schema.Not, visited)
	updates += normalizeEnumSchemaRefTypes(schema.Items, visited)
	for _, ref := range schema.Properties {
		updates += normalizeEnumSchemaRefTypes(ref, visited)
	}
	if schema.AdditionalProperties.Schema != nil {
		updates += normalizeEnumSchemaRefTypes(schema.AdditionalProperties.Schema, visited)
	}
	return updates
}

func normalizeEnumType(schema *openapi3.Schema) bool {
	if schema == nil || len(schema.Enum) == 0 {
		return false
	}

	allStrings := true
	allBooleans := true
	allNumbers := true
	allIntegers := true

	for _, item := range schema.Enum {
		switch v := item.(type) {
		case string:
			allBooleans = false
			allNumbers = false
			allIntegers = false
		case bool:
			allStrings = false
			allNumbers = false
			allIntegers = false
		case float64:
			allStrings = false
			allBooleans = false
			if math.Trunc(v) != v {
				allIntegers = false
			}
		default:
			return false
		}
	}

	var inferred string
	switch {
	case allStrings:
		inferred = "string"
	case allBooleans:
		inferred = "boolean"
	case allIntegers:
		inferred = "integer"
	case allNumbers:
		inferred = "number"
	default:
		return false
	}

	if schema.Type != nil && schema.Type.Is(inferred) {
		return false
	}

	schema.Type = &openapi3.Types{inferred}
	return true
}

func newStringPathParam(name string) *openapi3.ParameterRef {
	return &openapi3.ParameterRef{
		Value: &openapi3.Parameter{
			Name:     name,
			In:       openapi3.ParameterInPath,
			Required: true,
			Schema: &openapi3.SchemaRef{
				Value: &openapi3.Schema{
					Type: &openapi3.Types{"string"},
				},
			},
		},
	}
}

func writeJSON(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func writeText(path, value string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(value), 0o644)
}

func stateIsCurrent(path, sha string) bool {
	b, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(b)) == strings.TrimSpace(sha)
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
