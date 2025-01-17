package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		headers     http.Header
		want        string
		wantErr     error
		description string
	}{
		"success": {
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			want:        "abc123",
			wantErr:     nil,
			description: "should return API key when header is properly formatted",
		},
		"missing header": {
			headers:     http.Header{},
			want:        "",
			wantErr:     ErrNoAuthHeaderIncluded,
			description: "should return error when Authorization header is missing",
		},
		"malformed header - no type": {
			headers: http.Header{
				"Authorization": []string{"abc123"},
			},
			want:        "",
			wantErr:     errors.New("malformed authorization header"),
			description: "should return error when Authorization header is missing ApiKey type",
		},
		"malformed header - wrong type": {
			headers: http.Header{
				"Authorization": []string{"Bearer abc123"},
			},
			want:        "",
			wantErr:     errors.New("malformed authorization header"),
			description: "should return error when Authorization header has wrong type",
		},
		"empty header": {
			headers: http.Header{
				"Authorization": []string{""},
			},
			want:        "",
			wantErr:     ErrNoAuthHeaderIncluded,
			description: "should return error when Authorization header is empty",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.headers)

			if tc.wantErr != nil && err == nil {
				t.Errorf("expected error %v, got nil", tc.wantErr)
				return
			}

			if tc.wantErr == nil && err != nil {
				t.Errorf("expected no error, got %v", err)
				return
			}

			if tc.wantErr != nil && err != nil && tc.wantErr.Error() != err.Error() {
				t.Errorf("expected error %v, got %v", tc.wantErr, err)
				return
			}

			if got != tc.want {
				t.Errorf("expected %v, got %v", tc.want, got)
			}
		})
	}
}
