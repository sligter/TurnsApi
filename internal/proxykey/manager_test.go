package proxykey

import (
	"testing"
	"time"

	"turnsapi/internal/logger"
)

type stubConfigProvider struct {
	enabledGroups map[string]interface{}
}

func (s stubConfigProvider) GetEnabledGroups() map[string]interface{} {
	return s.enabledGroups
}

func TestRemoveGroupFromAllKeys_DisableIfNoExplicitGroupsRemain(t *testing.T) {
	m := &Manager{
		keys: map[string]*ProxyKey{
			"k1": {
				ID:            "k1",
				Key:           "k1-secret",
				Name:          "k1",
				IsActive:      true,
				AllowedGroups: []string{"g1", "g2"},
				GroupSelectionConfig: &GroupSelectionConfig{
					Strategy: GroupSelectionWeighted,
					GroupWeights: []GroupWeight{
						{GroupID: "g1", Weight: 3},
						{GroupID: "g2", Weight: 1},
					},
				},
			},
			"k2": {
				ID:                   "k2",
				Key:                  "k2-secret",
				Name:                 "k2",
				IsActive:             true,
				AllowedGroups:        []string{"g1"},
				GroupSelectionConfig: &GroupSelectionConfig{Strategy: GroupSelectionRoundRobin},
			},
			"k3": {
				ID:            "k3",
				Key:           "k3-secret",
				Name:          "k3",
				IsActive:      true,
				AllowedGroups: []string{}, // unrestricted
			},
		},
		groupSelectors: map[string]*GroupSelector{},
	}

	m.groupSelectors["k1"] = NewGroupSelector([]string{"g1", "g2"}, m.keys["k1"].GroupSelectionConfig)

	updated, disabled, err := m.RemoveGroupFromAllKeys("g1")
	if err != nil {
		t.Fatalf("RemoveGroupFromAllKeys returned error: %v", err)
	}

	if updated != 2 {
		t.Fatalf("expected updated=2, got %d", updated)
	}
	if disabled != 1 {
		t.Fatalf("expected disabled=1, got %d", disabled)
	}

	if got := len(m.keys["k1"].AllowedGroups); got != 1 || m.keys["k1"].AllowedGroups[0] != "g2" {
		t.Fatalf("k1 allowed groups mismatch, got=%v", m.keys["k1"].AllowedGroups)
	}
	if m.keys["k1"].GroupSelectionConfig != nil {
		t.Fatalf("k1 group selection config should be nil after only one group remains")
	}
	if _, exists := m.groupSelectors["k1"]; exists {
		t.Fatalf("k1 selector should be removed when only one group remains")
	}

	if len(m.keys["k2"].AllowedGroups) != 0 {
		t.Fatalf("k2 allowed groups should be empty after group removal, got=%v", m.keys["k2"].AllowedGroups)
	}
	if m.keys["k2"].IsActive {
		t.Fatalf("k2 should be disabled when explicit groups become empty")
	}
	if m.keys["k2"].GroupSelectionConfig != nil {
		t.Fatalf("k2 group selection config should be nil when key is disabled")
	}

	if len(m.keys["k3"].AllowedGroups) != 0 || !m.keys["k3"].IsActive {
		t.Fatalf("k3 should remain unchanged, got allowed=%v active=%v", m.keys["k3"].AllowedGroups, m.keys["k3"].IsActive)
	}
}

func TestRemoveGroupFromAllKeys_KeepWeightedConfigForRemainingGroups(t *testing.T) {
	m := &Manager{
		keys: map[string]*ProxyKey{
			"k1": {
				ID:            "k1",
				Key:           "k1-secret",
				Name:          "k1",
				IsActive:      true,
				AllowedGroups: []string{"g1", "g2", "g3"},
				GroupSelectionConfig: &GroupSelectionConfig{
					Strategy: GroupSelectionWeighted,
					GroupWeights: []GroupWeight{
						{GroupID: "g1", Weight: 5},
						{GroupID: "g2", Weight: 2},
						{GroupID: "g3", Weight: 3},
					},
				},
			},
		},
		groupSelectors: map[string]*GroupSelector{
			"k1": NewGroupSelector([]string{"g1", "g2", "g3"}, &GroupSelectionConfig{
				Strategy: GroupSelectionWeighted,
				GroupWeights: []GroupWeight{
					{GroupID: "g1", Weight: 5},
					{GroupID: "g2", Weight: 2},
					{GroupID: "g3", Weight: 3},
				},
			}),
		},
	}

	updated, disabled, err := m.RemoveGroupFromAllKeys("g2")
	if err != nil {
		t.Fatalf("RemoveGroupFromAllKeys returned error: %v", err)
	}

	if updated != 1 {
		t.Fatalf("expected updated=1, got %d", updated)
	}
	if disabled != 0 {
		t.Fatalf("expected disabled=0, got %d", disabled)
	}

	key := m.keys["k1"]
	if len(key.AllowedGroups) != 2 || key.AllowedGroups[0] != "g1" || key.AllowedGroups[1] != "g3" {
		t.Fatalf("remaining allowed groups mismatch: %v", key.AllowedGroups)
	}
	if key.GroupSelectionConfig == nil {
		t.Fatalf("group selection config should be kept for multi-group key")
	}
	if key.GroupSelectionConfig.Strategy != GroupSelectionWeighted {
		t.Fatalf("strategy should stay weighted, got %s", key.GroupSelectionConfig.Strategy)
	}
	if len(key.GroupSelectionConfig.GroupWeights) != 2 {
		t.Fatalf("expected 2 remaining group weights, got %d", len(key.GroupSelectionConfig.GroupWeights))
	}
	if key.GroupSelectionConfig.GroupWeights[0].GroupID != "g1" || key.GroupSelectionConfig.GroupWeights[1].GroupID != "g3" {
		t.Fatalf("remaining group weights mismatch: %+v", key.GroupSelectionConfig.GroupWeights)
	}
	if _, exists := m.groupSelectors["k1"]; !exists {
		t.Fatalf("selector should still exist for multi-group key")
	}
}

func TestManager_GetSortedEnabledGroupIDs(t *testing.T) {
	m := &Manager{
		configProvider: stubConfigProvider{
			enabledGroups: map[string]interface{}{
				"x666-me":    struct{}{},
				"cerebras":   struct{}{},
				"openrouter": struct{}{},
			},
		},
	}

	got := m.getSortedEnabledGroupIDs()
	want := []string{"cerebras", "openrouter", "x666-me"}
	if len(got) != len(want) {
		t.Fatalf("sorted groups length = %d, want %d (%v)", len(got), len(want), got)
	}
	for i, groupID := range want {
		if got[i] != groupID {
			t.Fatalf("sorted groups[%d] = %s, want %s (all=%v)", i, got[i], groupID, got)
		}
	}
}

func TestManager_SelectGroupForKey_UnrestrictedFallsBackToSortedFirstGroup(t *testing.T) {
	m := &Manager{
		keys: map[string]*ProxyKey{
			"k1": {
				ID:            "k1",
				Key:           "secret",
				Name:          "key-1",
				IsActive:      true,
				AllowedGroups: nil,
			},
		},
		groupSelectors: make(map[string]*GroupSelector),
		configProvider: stubConfigProvider{
			enabledGroups: map[string]interface{}{
				"openrouter": struct{}{},
				"cerebras":   struct{}{},
				"x666-me":    struct{}{},
			},
		},
	}

	got, err := m.SelectGroupForKey("k1")
	if err != nil {
		t.Fatalf("SelectGroupForKey() error = %v", err)
	}
	if got != "cerebras" {
		t.Fatalf("SelectGroupForKey() = %s, want cerebras", got)
	}
}

func TestManager_ValidateKeyReturnsEnforceModelMappings(t *testing.T) {
	now := time.Now()
	m := &Manager{
		keys: map[string]*ProxyKey{
			"k1": {
				ID:                   "k1",
				Key:                  "secret",
				Name:                 "key-1",
				IsActive:             true,
				EnforceModelMappings: true,
				CreatedAt:            now,
			},
		},
		groupSelectors: make(map[string]*GroupSelector),
	}

	got, ok := m.ValidateKey("secret")
	if !ok {
		t.Fatalf("ValidateKey() ok = false, want true")
	}

	dbKey, ok := got.(*logger.ProxyKey)
	if !ok {
		t.Fatalf("ValidateKey() type = %T, want *logger.ProxyKey", got)
	}
	if !dbKey.EnforceModelMappings {
		t.Fatalf("ValidateKey() EnforceModelMappings = false, want true")
	}
}
