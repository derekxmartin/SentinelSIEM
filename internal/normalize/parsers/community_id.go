package parsers

import (
	"github.com/derekxmartin/akeso-siem/internal/common"
)

// EnsureCommunityID copies the community_id from NDR session metadata to
// the top-level network.community_id field if it is not already set.
// This enables cross-source correlation: a query on network.community_id
// returns both NDR session metadata and any EDR/FW events sharing the same
// Community ID v1.0 flow identifier.
//
// This function is called by the NDR parser during normalization.
// Other parsers (EDR, syslog) can also call it if they compute community IDs.
func EnsureCommunityID(event *common.ECSEvent) {
	if event == nil {
		return
	}

	// Source 1: NDR session community_id.
	if event.NDR != nil && event.NDR.Session != nil && event.NDR.Session.CommunityID != "" {
		if event.Network == nil {
			event.Network = &common.NetworkFields{}
		}
		if event.Network.CommunityID == "" {
			event.Network.CommunityID = event.NDR.Session.CommunityID
		}
	}
}

// HasCommunityID checks whether an event has a community_id set at the
// network level, enabling cross-source pivot queries.
func HasCommunityID(event *common.ECSEvent) bool {
	return event != nil && event.Network != nil && event.Network.CommunityID != ""
}
