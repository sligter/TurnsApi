package keymanager

import (
	"testing"
)

func TestKeyManagerRoundRobinOrder(t *testing.T) {
	km := NewKeyManager([]string{"k1", "k2", "k3"}, "round_robin", 0, "")
	defer km.Close()

	want := []string{"k1", "k2", "k3", "k1"}
	for i, w := range want {
		got, err := km.GetNextKey()
		if err != nil {
			t.Fatalf("GetNextKey(%d) error: %v", i, err)
		}
		if got != w {
			t.Fatalf("GetNextKey(%d) = %q, want %q", i, got, w)
		}
	}
}

func TestKeyManagerRoundRobinSkipsInactive(t *testing.T) {
	km := NewKeyManager([]string{"k1", "k2", "k3"}, "round_robin", 0, "")
	defer km.Close()

	km.mutex.Lock()
	km.keyStatuses["k1"].IsActive = false
	km.mutex.Unlock()

	want := []string{"k2", "k3", "k2", "k3"}
	for i, w := range want {
		got, err := km.GetNextKey()
		if err != nil {
			t.Fatalf("GetNextKey(%d) error: %v", i, err)
		}
		if got != w {
			t.Fatalf("GetNextKey(%d) = %q, want %q", i, got, w)
		}
	}
}

func TestGroupKeyManagerRoundRobinSkipsInactive(t *testing.T) {
	gkm := NewGroupKeyManager("g1", "group1", []string{"k1", "k2", "k3"}, "round_robin")

	gkm.mutex.Lock()
	gkm.keyStatuses["k2"].IsActive = false
	gkm.mutex.Unlock()

	want := []string{"k1", "k3", "k1", "k3"}
	for i, w := range want {
		got, err := gkm.GetNextKey()
		if err != nil {
			t.Fatalf("GetNextKey(%d) error: %v", i, err)
		}
		if got != w {
			t.Fatalf("GetNextKey(%d) = %q, want %q", i, got, w)
		}
	}
}
