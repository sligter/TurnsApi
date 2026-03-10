package api

import "testing"

func TestParseOptionalJSONInt(t *testing.T) {
	tests := []struct {
		name         string
		value        interface{}
		defaultValue int
		want         int
		wantErr      bool
	}{
		{name: "nil uses default", value: nil, defaultValue: 30, want: 30},
		{name: "float64 number", value: float64(45), defaultValue: 30, want: 45},
		{name: "string number", value: "60", defaultValue: 30, want: 60},
		{name: "blank string uses default", value: " ", defaultValue: 30, want: 30},
		{name: "invalid string", value: "abc", defaultValue: 30, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseOptionalJSONInt(tt.value, tt.defaultValue, "timeout_seconds")
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %d, want %d", got, tt.want)
			}
		})
	}
}
