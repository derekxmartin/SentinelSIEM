package store

import "fmt"

// ECSIndexTemplate returns the index template body for ECS-compliant mappings.
// Applied to event, alert, and DLQ indices via index_patterns.
func ECSIndexTemplate(prefix string) map[string]any {
	return map[string]any{
		"index_patterns": []string{prefix + "-events-*", prefix + "-alerts-*", prefix + "-dlq-*"},
		"priority":       100,
		"template": map[string]any{
			"settings": map[string]any{
				"number_of_shards":   1,
				"number_of_replicas": 0,
				"index.lifecycle.name": prefix + "-ilm-policy",
			},
			"mappings": map[string]any{
				"dynamic": "false",
				"properties": ecsFieldMappings(),
			},
		},
	}
}

// ILMPolicy returns an ILM policy for event index lifecycle management.
func ILMPolicy(retentionDays int) map[string]any {
	return map[string]any{
		"policy": map[string]any{
			"phases": map[string]any{
				"hot": map[string]any{
					"actions": map[string]any{
						"rollover": map[string]any{
							"max_primary_shard_size": "50gb",
							"max_age":               "1d",
						},
					},
				},
				"delete": map[string]any{
					"min_age": fmt.Sprintf("%dd", retentionDays),
					"actions": map[string]any{
						"delete": map[string]any{},
					},
				},
			},
		},
	}
}

func ecsFieldMappings() map[string]any {
	return map[string]any{
		// Timestamp
		"@timestamp": mapping("date"),

		// event.*
		"event": map[string]any{
			"properties": map[string]any{
				"kind":     mapping("keyword"),
				"category": mapping("keyword"),
				"type":     mapping("keyword"),
				"action":   mapping("keyword"),
				"outcome":  mapping("keyword"),
				"severity": mapping("integer"),
			},
		},

		// process.*
		"process": map[string]any{
			"properties": map[string]any{
				"pid":          mapping("integer"),
				"name":         mapping("keyword"),
				"executable":   mapping("keyword"),
				"command_line": mapping("text"),
				"parent": map[string]any{
					"properties": map[string]any{
						"pid":          mapping("integer"),
						"name":         mapping("keyword"),
						"executable":   mapping("keyword"),
						"command_line": mapping("text"),
					},
				},
			},
		},

		// source.*
		"source": endpointMapping(),

		// destination.*
		"destination": endpointMapping(),

		// user.*
		"user": userMapping(),

		// host.*
		"host": map[string]any{
			"properties": map[string]any{
				"name": mapping("keyword"),
				"ip":   mapping("ip"),
				"os": map[string]any{
					"properties": map[string]any{
						"name":     mapping("keyword"),
						"platform": mapping("keyword"),
						"version":  mapping("keyword"),
					},
				},
			},
		},

		// file.*
		"file": map[string]any{
			"properties": map[string]any{
				"name": mapping("keyword"),
				"path": mapping("keyword"),
				"size": mapping("long"),
				"hash": map[string]any{
					"properties": map[string]any{
						"md5":    mapping("keyword"),
						"sha1":   mapping("keyword"),
						"sha256": mapping("keyword"),
					},
				},
			},
		},

		// registry.*
		"registry": map[string]any{
			"properties": map[string]any{
				"key":   mapping("keyword"),
				"value": mapping("keyword"),
				"data": map[string]any{
					"properties": map[string]any{
						"type":    mapping("keyword"),
						"strings": mapping("keyword"),
					},
				},
			},
		},

		// network.*
		"network": map[string]any{
			"properties": map[string]any{
				"protocol":  mapping("keyword"),
				"direction": mapping("keyword"),
				"bytes":     mapping("long"),
			},
		},

		// threat.*
		"threat": map[string]any{
			"properties": map[string]any{
				"technique": map[string]any{
					"type": "nested",
					"properties": map[string]any{
						"id":   mapping("keyword"),
						"name": mapping("keyword"),
					},
				},
			},
		},

		// dlp.* (custom extension)
		"dlp": map[string]any{
			"properties": map[string]any{
				"policy": map[string]any{
					"properties": map[string]any{
						"name":   mapping("keyword"),
						"action": mapping("keyword"),
					},
				},
				"classification": mapping("keyword"),
				"channel":        mapping("keyword"),
			},
		},

		// av.* (custom extension)
		"av": map[string]any{
			"properties": map[string]any{
				"scan": map[string]any{
					"properties": map[string]any{
						"result": mapping("keyword"),
						"engine": mapping("keyword"),
					},
				},
				"signature": map[string]any{
					"properties": map[string]any{
						"name": mapping("keyword"),
					},
				},
				"action": mapping("keyword"),
			},
		},

		// rule.* (ECS rule field set — used for alert documents)
		"rule": map[string]any{
			"properties": map[string]any{
				"id":          mapping("keyword"),
				"name":        mapping("keyword"),
				"description": mapping("text"),
				"category":    mapping("keyword"),
				"ruleset":     mapping("keyword"),
				"severity":    mapping("keyword"),
				"tags":        mapping("keyword"),
				"reference":   mapping("keyword"),
				"author":      mapping("keyword"),
			},
		},

		// raw — original event preserved as disabled (not indexed/searchable)
		"raw": map[string]any{
			"type":    "object",
			"enabled": false,
		},
	}
}

func mapping(esType string) map[string]any {
	return map[string]any{"type": esType}
}

func userMapping() map[string]any {
	return map[string]any{
		"properties": map[string]any{
			"name":   mapping("keyword"),
			"domain": mapping("keyword"),
			"id":     mapping("keyword"),
		},
	}
}

func endpointMapping() map[string]any {
	return map[string]any{
		"properties": map[string]any{
			"ip":     mapping("ip"),
			"port":   mapping("integer"),
			"domain": mapping("keyword"),
			"user":   userMapping(),
		},
	}
}
