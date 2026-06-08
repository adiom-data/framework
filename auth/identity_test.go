package auth

import "testing"

func TestNormalizeScopes(t *testing.T) {
	t.Parallel()

	got := NormalizeScopes([]string{"write", " read ", "write", "", "admin"})
	want := []string{"admin", "read", "write"}
	if len(got) != len(want) {
		t.Fatalf("scopes=%v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("scopes=%v want %v", got, want)
		}
	}
}
