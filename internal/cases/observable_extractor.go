package cases

import (
	"net"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// ExtractObservables extracts observables from an ECS-normalized event,
// tagging each with the source alert ID. Extracts IPs, file hashes,
// usernames, domains, process names, JA3/JA4, community IDs, and SNI.
func ExtractObservables(event *common.ECSEvent, alertID string) []Observable {
	var obs []Observable
	add := func(typ, value string) {
		if value == "" {
			return
		}
		obs = append(obs, Observable{
			Type:   typ,
			Value:  value,
			Source: alertID,
		})
	}

	// Source IP/domain.
	if event.Source != nil {
		if event.Source.IP != "" && isValidIP(event.Source.IP) {
			add(ObservableIP, event.Source.IP)
		}
		if event.Source.Domain != "" {
			add(ObservableDomain, event.Source.Domain)
		}
		if event.Source.User != nil && event.Source.User.Name != "" {
			add(ObservableUser, event.Source.User.Name)
		}
	}

	// Destination IP/domain.
	if event.Destination != nil {
		if event.Destination.IP != "" && isValidIP(event.Destination.IP) {
			add(ObservableIP, event.Destination.IP)
		}
		if event.Destination.Domain != "" {
			add(ObservableDomain, event.Destination.Domain)
		}
		if event.Destination.User != nil && event.Destination.User.Name != "" {
			add(ObservableUser, event.Destination.User.Name)
		}
	}

	// Host IPs.
	if event.Host != nil {
		for _, ip := range event.Host.IP {
			if isValidIP(ip) {
				add(ObservableIP, ip)
			}
		}
	}

	// User.
	if event.User != nil && event.User.Name != "" {
		add(ObservableUser, event.User.Name)
	}

	// File hashes.
	if event.File != nil && event.File.Hash != nil {
		add(ObservableHash, event.File.Hash.MD5)
		add(ObservableHash, event.File.Hash.SHA1)
		add(ObservableHash, event.File.Hash.SHA256)
	}

	// Process names.
	if event.Process != nil {
		add(ObservableProcess, event.Process.Name)
		if event.Process.Parent != nil {
			add(ObservableProcess, event.Process.Parent.Name)
		}
	}

	// DNS query domain.
	if event.DNS != nil && event.DNS.Question != nil && event.DNS.Question.Name != "" {
		add(ObservableDomain, event.DNS.Question.Name)
	}

	// TLS: JA3, JA4, SNI.
	if event.TLS != nil && event.TLS.Client != nil {
		add(ObservableJA3, event.TLS.Client.JA3)
		add(ObservableJA4, event.TLS.Client.JA4)
		add(ObservableSNI, event.TLS.Client.ServerName)
	}

	// Network community ID.
	if event.Network != nil && event.Network.CommunityID != "" {
		add(ObservableCommunityID, event.Network.CommunityID)
	}

	// NDR session community ID.
	if event.NDR != nil && event.NDR.Session != nil && event.NDR.Session.CommunityID != "" {
		add(ObservableCommunityID, event.NDR.Session.CommunityID)
	}

	return obs
}

// ExtractFromMultiple extracts and deduplicates observables from multiple events.
func ExtractFromMultiple(events []*common.ECSEvent, alertID string) []Observable {
	var all []Observable
	for _, event := range events {
		all = append(all, ExtractObservables(event, alertID)...)
	}
	return DeduplicateObservables(all)
}

// DeduplicateObservables removes duplicate observables by (type, value),
// keeping the first occurrence. Tags from duplicates are not merged since
// each observable already carries its source alert ID.
func DeduplicateObservables(obs []Observable) []Observable {
	seen := make(map[string]bool)
	result := make([]Observable, 0, len(obs))
	for _, o := range obs {
		key := o.Type + "|" + o.Value
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, o)
	}
	return result
}

// MergeObservables merges new observables into an existing set, deduplicating.
func MergeObservables(existing, incoming []Observable) []Observable {
	combined := make([]Observable, 0, len(existing)+len(incoming))
	combined = append(combined, existing...)
	combined = append(combined, incoming...)
	return DeduplicateObservables(combined)
}

// isValidIP returns true if s is a valid IPv4 or IPv6 address.
func isValidIP(s string) bool {
	return net.ParseIP(s) != nil
}
