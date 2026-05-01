package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		wantKey       string
		wantErrString string
	}{
		{
			name:    "Valid API Key",
			headers: http.Header{"Authorization": []string{"ApiKey secret-token-123"}},
			wantKey: "secret-token-123",
		},
		{
			name:          "No Authorization Header",
			headers:       http.Header{},
			wantErrString: ErrNoAuthHeaderIncluded.Error(),
		},
		{
			name:          "Malformed - Missing ApiKey prefix",
			headers:       http.Header{"Authorization": []string{"Bearer secret-token"}},
			wantErrString: "malformed authorization header",
		},
		{
			name:          "Malformed - Only prefix no key",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			wantErrString: "malformed authorization header",
		},
		{
			name:          "Malformed - Empty string",
			headers:       http.Header{"Authorization": []string{""}},
			wantErrString: ErrNoAuthHeaderIncluded.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			// Check error expectations
			if tt.wantErrString != "" {
				if err == nil {
					t.Errorf("GetAPIKey() error = nil, wantErr %v", tt.wantErrString)
					return
				}
				if err.Error() != tt.wantErrString {
					t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErrString)
					return
				}
			} else if err != nil {
				t.Errorf("GetAPIKey() unexpected error: %v", err)
				return
			}

			// Check result expectation
			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() = %v, want %v", gotKey, tt.wantKey)
			}
		})
	}
}
