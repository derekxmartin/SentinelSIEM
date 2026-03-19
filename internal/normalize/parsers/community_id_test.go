package parsers

import (
	"testing"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

func TestEnsureCommunityIDFromNDRSession(t *testing.T) {
	event := &common.ECSEvent{
		NDR: &common.NDRFields{
			Session: &common.NDRSession{
				CommunityID: "1:abc123",
			},
		},
	}

	EnsureCommunityID(event)

	if event.Network == nil {
		t.Fatal("network should be initialized")
	}
	if event.Network.CommunityID != "1:abc123" {
		t.Errorf("network.community_id = %q, want 1:abc123", event.Network.CommunityID)
	}
}

func TestEnsureCommunityIDPreservesExisting(t *testing.T) {
	event := &common.ECSEvent{
		Network: &common.NetworkFields{
			CommunityID: "1:existing",
		},
		NDR: &common.NDRFields{
			Session: &common.NDRSession{
				CommunityID: "1:different",
			},
		},
	}

	EnsureCommunityID(event)

	if event.Network.CommunityID != "1:existing" {
		t.Errorf("network.community_id = %q, should preserve existing", event.Network.CommunityID)
	}
}

func TestEnsureCommunityIDNilEvent(t *testing.T) {
	// Should not panic.
	EnsureCommunityID(nil)
}

func TestEnsureCommunityIDNoNDR(t *testing.T) {
	event := &common.ECSEvent{}
	EnsureCommunityID(event)

	if event.Network != nil {
		t.Error("network should remain nil when no community_id source exists")
	}
}

func TestEnsureCommunityIDEmptyCommunityID(t *testing.T) {
	event := &common.ECSEvent{
		NDR: &common.NDRFields{
			Session: &common.NDRSession{
				CommunityID: "",
			},
		},
	}

	EnsureCommunityID(event)

	if event.Network != nil {
		t.Error("network should remain nil when community_id is empty")
	}
}

func TestHasCommunityID(t *testing.T) {
	tests := []struct {
		name     string
		event    *common.ECSEvent
		expected bool
	}{
		{"nil event", nil, false},
		{"no network", &common.ECSEvent{}, false},
		{"empty community_id", &common.ECSEvent{Network: &common.NetworkFields{}}, false},
		{"has community_id", &common.ECSEvent{Network: &common.NetworkFields{CommunityID: "1:x"}}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasCommunityID(tc.event); got != tc.expected {
				t.Errorf("HasCommunityID() = %v, want %v", got, tc.expected)
			}
		})
	}
}
