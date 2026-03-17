package search

// BuildEventQuery returns an ES search body for the events index.
// Returns counts + source-type aggregation only (size: 0).
func BuildEventQuery(query, entityType, timeFrom, timeTo string) map[string]any {
	must := entityFilter(query, entityType, eventFieldsForEntity(entityType))
	body := map[string]any{
		"size": 0,
		"query": map[string]any{
			"bool": withTimeRange(must, timeFrom, timeTo),
		},
		"aggs": map[string]any{
			"by_source": map[string]any{
				"terms": map[string]any{
					"field": "event.category",
					"size":  20,
				},
			},
		},
	}
	return body
}

// BuildAlertQuery returns an ES search body for the alerts index (max 5 results).
func BuildAlertQuery(query, entityType, timeFrom, timeTo string) map[string]any {
	must := entityFilter(query, entityType, alertFieldsForEntity(entityType))
	return map[string]any{
		"size": 5,
		"sort": []map[string]any{{"@timestamp": map[string]string{"order": "desc"}}},
		"query": map[string]any{
			"bool": withTimeRange(must, timeFrom, timeTo),
		},
	}
}

// BuildCaseQuery returns an ES search body for the cases index (max 5 results).
func BuildCaseQuery(query, entityType string) map[string]any {
	fields := []string{"title", "observables.value", "tags"}
	if entityType == EntityCaseID {
		// Direct ID lookup.
		return map[string]any{
			"size": 5,
			"query": map[string]any{
				"term": map[string]any{"_id": query},
			},
		}
	}
	return map[string]any{
		"size": 5,
		"sort": []map[string]any{{"updated_at": map[string]string{"order": "desc"}}},
		"query": map[string]any{
			"multi_match": map[string]any{
				"query":  query,
				"fields": fields,
				"type":   "phrase_prefix",
			},
		},
	}
}

// BuildHostScoreQuery returns an ES search body for the host-scores index.
func BuildHostScoreQuery(query string) map[string]any {
	return map[string]any{
		"size": 5,
		"query": map[string]any{
			"term": map[string]any{"host.ip": query},
		},
	}
}

// entityFilter builds the core query clause for an entity type search.
func entityFilter(query, entityType string, fields []string) map[string]any {
	if len(fields) == 0 {
		return map[string]any{
			"multi_match": map[string]any{
				"query":  query,
				"fields": fields,
				"type":   "best_fields",
			},
		}
	}

	switch entityType {
	case EntityIP, EntitySHA256, EntitySHA1, EntityMD5JA3, EntityCommunityID, EntityUsername:
		// Keyword fields — use term queries with should (OR).
		should := make([]map[string]any, len(fields))
		for i, f := range fields {
			should[i] = map[string]any{"term": map[string]any{f: query}}
		}
		return map[string]any{
			"bool": map[string]any{
				"should":               should,
				"minimum_should_match": 1,
			},
		}
	case EntityDomain:
		should := make([]map[string]any, len(fields))
		for i, f := range fields {
			should[i] = map[string]any{"term": map[string]any{f: query}}
		}
		return map[string]any{
			"bool": map[string]any{
				"should":               should,
				"minimum_should_match": 1,
			},
		}
	case EntityPath:
		should := make([]map[string]any, len(fields))
		for i, f := range fields {
			should[i] = map[string]any{"term": map[string]any{f: query}}
		}
		return map[string]any{
			"bool": map[string]any{
				"should":               should,
				"minimum_should_match": 1,
			},
		}
	case EntityAlertID:
		return map[string]any{
			"term": map[string]any{"_id": query},
		}
	default:
		// Free text — multi_match across text fields.
		return map[string]any{
			"multi_match": map[string]any{
				"query":  query,
				"fields": fields,
				"type":   "phrase_prefix",
			},
		}
	}
}

// withTimeRange wraps a query clause in a bool with a time range filter.
func withTimeRange(queryClause map[string]any, timeFrom, timeTo string) map[string]any {
	boolClause := map[string]any{
		"must": queryClause,
	}
	if timeFrom != "" || timeTo != "" {
		rangeFilter := map[string]any{}
		if timeFrom != "" {
			rangeFilter["gte"] = timeFrom
		}
		if timeTo != "" {
			rangeFilter["lte"] = timeTo
		}
		boolClause["filter"] = []map[string]any{
			{"range": map[string]any{"@timestamp": rangeFilter}},
		}
	}
	return boolClause
}

// eventFieldsForEntity returns the ECS fields to search in the events index.
func eventFieldsForEntity(entityType string) []string {
	switch entityType {
	case EntityIP:
		return []string{"source.ip", "destination.ip", "host.ip"}
	case EntitySHA256:
		return []string{"file.hash.sha256"}
	case EntitySHA1:
		return []string{"file.hash.sha1"}
	case EntityMD5JA3:
		return []string{"file.hash.md5"}
	case EntityCommunityID:
		return []string{"network.community_id"}
	case EntityDomain:
		return []string{"host.name", "url.domain"}
	case EntityPath:
		return []string{"file.path", "process.executable"}
	case EntityUsername:
		return []string{"user.name"}
	default:
		return []string{"event.action", "process.command_line", "rule.name"}
	}
}

// alertFieldsForEntity returns the fields to search in the alerts index.
func alertFieldsForEntity(entityType string) []string {
	switch entityType {
	case EntityIP:
		return []string{"source.ip", "destination.ip", "host.ip"}
	case EntitySHA256:
		return []string{"file.hash.sha256"}
	case EntitySHA1:
		return []string{"file.hash.sha1"}
	case EntityMD5JA3:
		return []string{"file.hash.md5"}
	case EntityUsername:
		return []string{"user.name"}
	case EntityAlertID:
		return []string{"_id"}
	default:
		return []string{"rule.name", "rule.description"}
	}
}
