package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKeyValid(t *testing.T) {
	headers := http.Header{"Authorization": {"ApiKey my-secret-key"}}
	expectedKey := "my-secret-key"
	key, err := GetAPIKey(headers)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if key != expectedKey {
		t.Fatalf("expected key: %v, got: %v", expectedKey, key)
	}
}

func TestGetAPIKeyNoHeader(t *testing.T) {
	headers := http.Header{}
	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected error, got none")
	}
	if err != ErrNoAuthHeaderIncluded {
		t.Fatalf("expected error: %v, got: %v", ErrNoAuthHeaderIncluded, err)
	}
}

func TestGetAPIKeyMalformedHeaderNoApiKey(t *testing.T) {
	headers := http.Header{"Authorization": {"Bearer my-secret-key"}}
	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected error, got none")
	}
	if err.Error() != "malformed authorization header" {
		t.Fatalf("expected error: %v, got: %v", "malformed authorization header", err)
	}
}

func TestGetAPIKeyMalformedHeaderMissingKey(t *testing.T) {
	headers := http.Header{"Authorization": {"ApiKey"}}
	_, err := GetAPIKey(headers)
	if err == nil {
		t.Fatal("expected error, got none")
	}
	if err.Error() != "malformed authorization header" {
		t.Fatalf("expected error: %v, got: %v", "malformed authorization header", err)
	}
}
