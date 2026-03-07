package proxykey

import (
	"testing"
)

func TestGroupSelector_RoundRobin(t *testing.T) {
	allowedGroups := []string{"group1", "group2", "group3"}
	config := &GroupSelectionConfig{
		Strategy: GroupSelectionRoundRobin,
	}

	selector := NewGroupSelector(allowedGroups, config)

	// 测试轮询选择
	expected := []string{"group1", "group2", "group3", "group1", "group2", "group3"}
	for i, expectedGroup := range expected {
		selectedGroup, err := selector.SelectGroup()
		if err != nil {
			t.Fatalf("SelectGroup() error = %v", err)
		}
		if selectedGroup != expectedGroup {
			t.Errorf("SelectGroup() iteration %d = %v, want %v", i, selectedGroup, expectedGroup)
		}
	}
}

func TestGroupSelector_Weighted(t *testing.T) {
	allowedGroups := []string{"group1", "group2"}
	config := &GroupSelectionConfig{
		Strategy: GroupSelectionWeighted,
		GroupWeights: []GroupWeight{
			{GroupID: "group1", Weight: 3},
			{GroupID: "group2", Weight: 1},
		},
	}

	selector := NewGroupSelector(allowedGroups, config)

	// 测试权重选择 - 进行多次选择并统计分布
	selections := make(map[string]int)
	totalSelections := 1000

	for i := 0; i < totalSelections; i++ {
		selectedGroup, err := selector.SelectGroup()
		if err != nil {
			t.Fatalf("SelectGroup() error = %v", err)
		}
		selections[selectedGroup]++
	}

	// 验证权重比例大致正确（允许一定误差）
	group1Ratio := float64(selections["group1"]) / float64(totalSelections)
	group2Ratio := float64(selections["group2"]) / float64(totalSelections)

	expectedGroup1Ratio := 0.75 // 3/(3+1)
	expectedGroup2Ratio := 0.25 // 1/(3+1)

	tolerance := 0.1 // 10%的误差容忍度

	if abs(group1Ratio-expectedGroup1Ratio) > tolerance {
		t.Errorf("Group1 ratio = %v, want approximately %v", group1Ratio, expectedGroup1Ratio)
	}

	if abs(group2Ratio-expectedGroup2Ratio) > tolerance {
		t.Errorf("Group2 ratio = %v, want approximately %v", group2Ratio, expectedGroup2Ratio)
	}
}

func TestGroupSelector_SingleGroup(t *testing.T) {
	allowedGroups := []string{"group1"}
	config := &GroupSelectionConfig{
		Strategy: GroupSelectionRoundRobin,
	}

	selector := NewGroupSelector(allowedGroups, config)

	// 单个分组应该总是返回该分组
	for i := 0; i < 5; i++ {
		selectedGroup, err := selector.SelectGroup()
		if err != nil {
			t.Fatalf("SelectGroup() error = %v", err)
		}
		if selectedGroup != "group1" {
			t.Errorf("SelectGroup() = %v, want group1", selectedGroup)
		}
	}
}

func TestGroupSelector_EmptyGroups(t *testing.T) {
	allowedGroups := []string{}
	config := &GroupSelectionConfig{
		Strategy: GroupSelectionRoundRobin,
	}

	selector := NewGroupSelector(allowedGroups, config)

	// 空分组列表应该返回错误
	_, err := selector.SelectGroup()
	if err == nil {
		t.Error("SelectGroup() expected error for empty groups, got nil")
	}
}

func TestGroupSelector_Random(t *testing.T) {
	allowedGroups := []string{"group1", "group2", "group3"}
	config := &GroupSelectionConfig{
		Strategy: GroupSelectionRandom,
	}

	selector := NewGroupSelector(allowedGroups, config)

	// 测试随机选择 - 验证所有分组都能被选中
	selections := make(map[string]bool)
	maxAttempts := 100

	for i := 0; i < maxAttempts; i++ {
		selectedGroup, err := selector.SelectGroup()
		if err != nil {
			t.Fatalf("SelectGroup() error = %v", err)
		}
		selections[selectedGroup] = true

		// 如果所有分组都被选中过，测试通过
		if len(selections) == len(allowedGroups) {
			break
		}
	}

	if len(selections) != len(allowedGroups) {
		t.Errorf("Random selection didn't select all groups after %d attempts. Selected: %v", maxAttempts, selections)
	}
}

func TestGroupSelector_Failover(t *testing.T) {
	allowedGroups := []string{"group1", "group2", "group3"}
	config := &GroupSelectionConfig{
		Strategy: GroupSelectionFailover,
	}

	selector := NewGroupSelector(allowedGroups, config)

	// 故障转移策略应该总是选择第一个分组
	for i := 0; i < 5; i++ {
		selectedGroup, err := selector.SelectGroup()
		if err != nil {
			t.Fatalf("SelectGroup() error = %v", err)
		}
		if selectedGroup != "group1" {
			t.Errorf("SelectGroup() = %v, want group1 (first group)", selectedGroup)
		}
	}
}

func TestGroupSelector_UpdateConfig(t *testing.T) {
	allowedGroups := []string{"group1", "group2"}
	config := &GroupSelectionConfig{
		Strategy: GroupSelectionRoundRobin,
	}

	selector := NewGroupSelector(allowedGroups, config)

	// 初始轮询测试
	group1, _ := selector.SelectGroup()
	group2, _ := selector.SelectGroup()
	if group1 != "group1" || group2 != "group2" {
		t.Errorf("Initial round robin failed: got %v, %v", group1, group2)
	}

	// 更新为权重策略
	newConfig := &GroupSelectionConfig{
		Strategy: GroupSelectionWeighted,
		GroupWeights: []GroupWeight{
			{GroupID: "group1", Weight: 1},
			{GroupID: "group2", Weight: 0}, // 权重为0，应该被设为默认权重1
		},
	}

	selector.UpdateConfig(newConfig)

	// 验证配置更新生效
	selections := make(map[string]int)
	for i := 0; i < 100; i++ {
		selectedGroup, _ := selector.SelectGroup()
		selections[selectedGroup]++
	}

	// 由于两个分组权重相同，应该大致均匀分布
	if selections["group1"] == 0 || selections["group2"] == 0 {
		t.Errorf("After config update, both groups should be selected. Got: %v", selections)
	}
}

// abs 返回浮点数的绝对值
func TestGroupSelector_SelectGroupFromCandidatesRoundRobin(t *testing.T) {
	selector := NewGroupSelector([]string{"group1", "group2", "group3"}, &GroupSelectionConfig{
		Strategy: GroupSelectionRoundRobin,
	})

	got1, err := selector.SelectGroupFromCandidates([]string{"group2", "group3"})
	if err != nil {
		t.Fatalf("SelectGroupFromCandidates() error = %v", err)
	}
	if got1 != "group2" {
		t.Fatalf("first candidate selection = %s, want group2", got1)
	}

	got2, err := selector.SelectGroupFromCandidates([]string{"group2", "group3"})
	if err != nil {
		t.Fatalf("SelectGroupFromCandidates() error = %v", err)
	}
	if got2 != "group3" {
		t.Fatalf("second candidate selection = %s, want group3", got2)
	}

	got3, err := selector.SelectGroupFromCandidates([]string{"group2", "group3"})
	if err != nil {
		t.Fatalf("SelectGroupFromCandidates() error = %v", err)
	}
	if got3 != "group2" {
		t.Fatalf("third candidate selection = %s, want group2", got3)
	}
}

func TestGroupSelector_SelectGroupFromCandidatesFailover(t *testing.T) {
	selector := NewGroupSelector([]string{"group1", "group2", "group3"}, &GroupSelectionConfig{
		Strategy: GroupSelectionFailover,
	})

	got, err := selector.SelectGroupFromCandidates([]string{"group3", "group2"})
	if err != nil {
		t.Fatalf("SelectGroupFromCandidates() error = %v", err)
	}
	if got != "group2" {
		t.Fatalf("failover candidate selection = %s, want group2", got)
	}
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
