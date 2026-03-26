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

func TestKeyManagerRoundRobinSkipsInvalid(t *testing.T) {
	km := NewKeyManager([]string{"k1", "k2", "k3"}, "round_robin", 0, "")
	defer km.Close()

	invalid := false
	km.mutex.Lock()
	km.keyStatuses["k2"].IsValid = &invalid
	km.mutex.Unlock()

	want := []string{"k1", "k3", "k1", "k3"}
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

func TestGroupKeyManagerRoundRobinSkipsInvalid(t *testing.T) {
	gkm := NewGroupKeyManager("g1", "group1", []string{"k1", "k2", "k3"}, "round_robin")

	invalid := false
	gkm.mutex.Lock()
	gkm.keyStatuses["k2"].IsValid = &invalid
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

func TestGroupKeyManagerDisablePermanentBanKeepsKeyActive(t *testing.T) {
	gkm := NewGroupKeyManagerWithConfig(GroupKeyManagerConfig{
		GroupID:             "g1",
		GroupName:           "group1",
		Keys:                []string{"k1"},
		RotationStrategy:    "round_robin",
		DisablePermanentBan: true,
		MaxErrorCount:       2,
	})

	gkm.ReportError("k1", "upstream error")
	gkm.ReportError("k1", "upstream error")

	status := gkm.GetKeyStatuses()["k1"]
	if status == nil {
		t.Fatalf("expected key status for k1")
	}
	if !status.IsActive {
		t.Fatalf("key should remain active when DisablePermanentBan is enabled")
	}
	if status.ErrorCount != 2 {
		t.Fatalf("ErrorCount = %d, want 2", status.ErrorCount)
	}
}
