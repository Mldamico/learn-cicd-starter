package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {

	t.Run("valid api key", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey 12345")

		key, err := GetAPIKey(headers)

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if key != "12345" {
			t.Errorf("expected '12345', got '%s'", key)
		}
	})

	t.Run("missing authorization header", func(t *testing.T) {
		headers := http.Header{}

		_, err := GetAPIKey(headers)

		if err == nil {
			t.Fatal("expected error, got nil")
		}

		if err != ErrNoAuthHeaderIncluded {
			t.Errorf("expected ErrNoAuthHeaderIncluded, got %v", err)
		}
	})

	t.Run("malformed header - no value", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey")

		_, err := GetAPIKey(headers)

		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("malformed header - wrong prefix", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "Bearer 12345")

		_, err := GetAPIKey(headers)

		if err == nil {
			t.Fatal("expected error, got nil")
		}
	})

	t.Run("extra spaces", func(t *testing.T) {
		headers := http.Header{}
		headers.Set("Authorization", "ApiKey    12345")

		key, err := GetAPIKey(headers)

		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}

		if key != "" {
			t.Errorf("expected empty string due to split behavior, got '%s'", key)
		}
	})
}