package oidcfinder

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestFetchJSONStrictDecoding(t *testing.T) {
	for _, tc := range []struct {
		name  string
		body  string
		valid bool
	}{
		{"valid", `{"keys":[{"kty":"RSA"}]}`, true},
		{"duplicate key", `{"keys":[],"keys":[{"kty":"RSA"}]}`, false},
		{"nested duplicate key", `{"keys":[{"kty":"RSA","kty":"EC"}]}`, false},
		{"invalid UTF-8", "{\"keys\":[{\"kty\":\"\xff\"}]}", false},
		{"trailing value", `{"keys":[]} {}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
				return response(r, 200, tc.body), nil
			})}
			var out struct {
				Keys []map[string]any `json:"keys"`
			}
			err := fetchJSON(context.Background(), client, "https://example.com/keys", &out)
			if tc.valid {
				if err != nil || len(out.Keys) != 1 {
					t.Fatalf("valid response: keys=%v, error=%v", out.Keys, err)
				}
			} else {
				var fetchErr *fetchError
				if !errors.As(err, &fetchErr) || fetchErr.kind != "invalid" {
					t.Fatalf("expected invalid response, got %v", err)
				}
			}
		})
	}
}

func TestScanRequiresExactJWKSFieldName(t *testing.T) {
	client := &http.Client{Transport: transportFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path == "/keys" {
			return response(r, 200, `{"Keys":[{"kty":"RSA"}]}`), nil
		}
		return response(r, 200, `{"issuer":"https://example.com","jwks_uri":"https://example.com/keys","token_endpoint":"https://example.com/token"}`), nil
	})}
	out := scan(context.Background(), client, target{Host: "example.com"}, nil)
	if len(out.found) != 0 {
		t.Fatalf("accepted JWKS with incorrectly cased keys: %+v", out.found)
	}
}

func TestStatusJSONOutput(t *testing.T) {
	var output bytes.Buffer
	if err := Run([]string{"status", "--db", filepath.Join(t.TempDir(), "status.db")}, &output, &output); err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"Targets\": 0,\n  \"Due\": 0,\n  \"Pending\": 0,\n  \"Accepted\": 0,\n  \"Rejected\": 0,\n  \"CatalogCandidates\": 0,\n  \"CatalogEntries\": 0,\n  \"CatalogFetched\": \"\",\n  \"Results\": {}\n}\n"
	if output.String() != want {
		t.Fatalf("unexpected status output:\n%s", strings.TrimSpace(output.String()))
	}
}
