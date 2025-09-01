package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	testCases := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr error
	}{
		{
			name: "valid case",
			headers: http.Header{
				"Authorization": {"ApiKey my-secret-key"},
			},
			wantKey: "something-wrong",
			wantErr: nil,
		},
		{
			name:    "no auth header",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "malformed header",
			headers: http.Header{
				"Authorization": {"Bearer my-secret-key"},
			},
			wantKey: "",
			wantErr: new(malformedAuthHeaderError), // A placeholder for any malformed error
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tc.headers)

			if gotKey != tc.wantKey {
				t.Errorf("expected key '%s', got '%s'", tc.wantKey, gotKey)
			}

			// Simpler error checking
			if tc.wantErr == nil && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
			if tc.wantErr != nil && err == nil {
				t.Errorf("expected error %v, got nil", tc.wantErr)
			}
			// This check is useful if you want to ensure the error type is correct
			// without worrying about the exact error message in the malformed case.
			if err != nil && tc.wantErr != nil && err.Error() != tc.wantErr.Error() {
				// For the "malformed" case, we just check if any error of that type occurred.
				if _, ok := tc.wantErr.(*malformedAuthHeaderError); ok {
					if err.Error() != "malformed authorization header" {
						t.Errorf("expected malformed error, got: %v", err)
					}
				} else { // For specific errors like ErrNoAuthHeaderIncluded
					t.Errorf("expected error '%v', got '%v'", tc.wantErr, err)
				}
			}
		})
	}
}

// Custom error type for easier comparison of malformed header errors
type malformedAuthHeaderError struct{}

func (e *malformedAuthHeaderError) Error() string {
	return "malformed authorization header"
}
