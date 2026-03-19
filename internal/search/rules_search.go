package search

import (
	"strings"

	"github.com/derekxmartin/akeso-siem/internal/correlate"
)

// SearchRules performs a case-insensitive substring match on rule Title
// and Description, returning up to maxResults matches.
func SearchRules(rules []*correlate.SigmaRule, query string, maxResults int) []RuleResult {
	if len(rules) == 0 || query == "" {
		return nil
	}

	q := strings.ToLower(query)
	var results []RuleResult

	for _, r := range rules {
		if len(results) >= maxResults {
			break
		}
		title := strings.ToLower(r.Title)
		desc := strings.ToLower(r.Description)
		if strings.Contains(title, q) || strings.Contains(desc, q) {
			results = append(results, RuleResult{
				ID:          r.ID,
				Name:        r.Title,
				Description: r.Description,
				Severity:    r.Level,
			})
		}
	}

	return results
}
