package correlate

import (
	"fmt"
	"strings"

	"github.com/derekxmartin/akeso-siem/internal/common"
)

// CompiledDetection is a pre-compiled form of a SigmaDetection ready for
// efficient evaluation. It holds the parsed condition AST and any
// pre-compiled modifiers (regex, CIDR) for each selection.
type CompiledDetection struct {
	condition  ConditionExpr
	selections map[string][]compiledEventMatcher
}

// compiledEventMatcher is the compiled form of a SigmaEventMatcher.
type compiledEventMatcher struct {
	fields []compiledFieldMatcher
}

// compiledFieldMatcher is the compiled form of a SigmaFieldMatcher.
type compiledFieldMatcher struct {
	field    string
	matcher  fieldMatchFunc
	original SigmaFieldMatcher // keep for debugging
}

// fieldMatchFunc tests whether an event field value satisfies the matcher.
// The value is the raw field value extracted from the event (string, int, etc.).
// Returns true if the match succeeds.
type fieldMatchFunc func(value interface{}) bool

// CompileDetection pre-compiles a SigmaDetection into a form suitable for
// repeated evaluation. This is called once at rule-load time.
func CompileDetection(det *SigmaDetection) (*CompiledDetection, error) {
	if det == nil {
		return nil, fmt.Errorf("nil detection")
	}

	// Parse the condition string into an AST.
	cond, err := parseCondition(det.Condition)
	if err != nil {
		return nil, fmt.Errorf("condition %q: %w", det.Condition, err)
	}

	// Compile each selection.
	compiled := &CompiledDetection{
		condition:  cond,
		selections: make(map[string][]compiledEventMatcher, len(det.Selections)),
	}

	for name, sel := range det.Selections {
		var matchers []compiledEventMatcher
		for _, em := range sel {
			cm, err := compileEventMatcher(em)
			if err != nil {
				return nil, fmt.Errorf("selection %q: %w", name, err)
			}
			matchers = append(matchers, cm)
		}
		compiled.selections[name] = matchers
	}

	return compiled, nil
}

// compileEventMatcher compiles a single event matcher.
func compileEventMatcher(em SigmaEventMatcher) (compiledEventMatcher, error) {
	var fields []compiledFieldMatcher
	for _, fm := range em.FieldMatchers {
		matchFn, err := compileFieldMatcher(fm)
		if err != nil {
			return compiledEventMatcher{}, fmt.Errorf("field %q: %w", fm.Field, err)
		}
		fields = append(fields, compiledFieldMatcher{
			field:    fm.Field,
			matcher:  matchFn,
			original: fm,
		})
	}
	return compiledEventMatcher{fields: fields}, nil
}

// compileFieldMatcher builds a fieldMatchFunc for a SigmaFieldMatcher.
func compileFieldMatcher(fm SigmaFieldMatcher) (fieldMatchFunc, error) {
	return buildModifierChain(fm.Modifiers, fm.Values)
}

// EvaluateEvent evaluates a compiled detection against an ECS event.
// Returns true if the event matches the rule's detection logic.
func EvaluateEvent(compiled *CompiledDetection, event *common.ECSEvent) bool {
	if compiled == nil || event == nil {
		return false
	}

	// Build a map of selection results.
	selResults := make(map[string]bool, len(compiled.selections))
	for name, matchers := range compiled.selections {
		// A selection matches if ANY event matcher (OR) matches.
		selResults[name] = evaluateSelection(matchers, event)
	}

	// Evaluate the condition AST against the selection results.
	return compiled.condition.Eval(selResults)
}

// evaluateSelection evaluates a compiled selection (list of event matchers, OR'd).
func evaluateSelection(matchers []compiledEventMatcher, event *common.ECSEvent) bool {
	for _, cm := range matchers {
		if evaluateEventMatcher(cm, event) {
			return true
		}
	}
	return false
}

// evaluateEventMatcher evaluates a single event matcher (all fields AND'd).
func evaluateEventMatcher(cm compiledEventMatcher, event *common.ECSEvent) bool {
	for _, fm := range cm.fields {
		val, found := getEventFieldValue(event, fm.field)
		if !found {
			// Field not present → match fails for this matcher.
			return false
		}
		if !fm.matcher(val) {
			return false
		}
	}
	return true
}

// getEventFieldValue extracts a field value from an ECSEvent by its dotted path.
// It uses explicit mapping rather than reflection for performance and type safety.
// Returns the value and true if found, or nil and false if the field doesn't exist
// or the containing struct is nil.
func getEventFieldValue(event *common.ECSEvent, field string) (interface{}, bool) {
	parts := strings.SplitN(field, ".", 2)
	topLevel := parts[0]
	rest := ""
	if len(parts) > 1 {
		rest = parts[1]
	}

	switch topLevel {
	case "event":
		return getEventSubfield(event.Event, rest)
	case "process":
		return getProcessSubfield(event.Process, rest)
	case "source":
		return getEndpointSubfield(event.Source, rest)
	case "destination":
		return getEndpointSubfield(event.Destination, rest)
	case "user":
		return getUserSubfield(event.User, rest)
	case "host":
		return getHostSubfield(event.Host, rest)
	case "file":
		return getFileSubfield(event.File, rest)
	case "registry":
		return getRegistrySubfield(event.Registry, rest)
	case "network":
		return getNetworkSubfield(event.Network, rest)
	case "threat":
		return getThreatSubfield(event.Threat, rest)
	case "dlp":
		return getDLPSubfield(event.DLP, rest)
	case "av":
		return getAVSubfield(event.AV, rest)
	case "dns":
		return getDNSSubfield(event.DNS, rest)
	case "http":
		return getHTTPSubfield(event.HTTP, rest)
	case "tls":
		return getTLSSubfield(event.TLS, rest)
	case "url":
		return getURLSubfield(event.URL, rest)
	case "user_agent":
		return getUserAgentSubfield(event.UserAgent, rest)
	case "smb":
		return getSMBSubfield(event.SMB, rest)
	case "kerberos":
		return getKerberosSubfield(event.Kerberos, rest)
	case "ssh":
		return getSSHSubfield(event.SSH, rest)
	case "ndr":
		return getNDRSubfield(event.NDR, rest)
	case "observer":
		return getObserverSubfield(event.Observer, rest)
	case "rule":
		return getRuleSubfield(event.Rule, rest)
	case "log":
		return getLogSubfield(event.Log, rest)
	case "winevt":
		return getWinEvtSubfield(event.WinEvt, rest)
	default:
		return nil, false
	}
}

// --- Subfield extractors ---

func getEventSubfield(e *common.EventFields, field string) (interface{}, bool) {
	if e == nil {
		return nil, false
	}
	switch field {
	case "kind":
		return e.Kind, e.Kind != ""
	case "category":
		if len(e.Category) > 0 {
			return e.Category, true
		}
		return nil, false
	case "type":
		if len(e.Type) > 0 {
			return e.Type, true
		}
		return nil, false
	case "action":
		return e.Action, e.Action != ""
	case "outcome":
		return e.Outcome, e.Outcome != ""
	case "severity":
		return e.Severity, true
	default:
		return nil, false
	}
}

func getProcessSubfield(p *common.ProcessFields, field string) (interface{}, bool) {
	if p == nil {
		return nil, false
	}
	parts := strings.SplitN(field, ".", 2)
	switch parts[0] {
	case "pid":
		return p.PID, true
	case "name":
		return p.Name, p.Name != ""
	case "executable":
		return p.Executable, p.Executable != ""
	case "command_line":
		return p.CommandLine, p.CommandLine != ""
	case "parent":
		if p.Parent == nil {
			return nil, false
		}
		if len(parts) < 2 {
			return nil, false
		}
		switch parts[1] {
		case "pid":
			return p.Parent.PID, true
		case "name":
			return p.Parent.Name, p.Parent.Name != ""
		case "executable":
			return p.Parent.Executable, p.Parent.Executable != ""
		case "command_line":
			return p.Parent.CommandLine, p.Parent.CommandLine != ""
		default:
			return nil, false
		}
	default:
		return nil, false
	}
}

func getEndpointSubfield(e *common.EndpointFields, field string) (interface{}, bool) {
	if e == nil {
		return nil, false
	}
	parts := strings.SplitN(field, ".", 2)
	switch parts[0] {
	case "ip":
		return e.IP, e.IP != ""
	case "port":
		return e.Port, true
	case "domain":
		return e.Domain, e.Domain != ""
	case "address":
		return e.Address, e.Address != ""
	case "user":
		if e.User == nil {
			return nil, false
		}
		if len(parts) < 2 {
			return nil, false
		}
		return getUserSubfield(e.User, parts[1])
	default:
		return nil, false
	}
}

func getUserSubfield(u *common.UserFields, field string) (interface{}, bool) {
	if u == nil {
		return nil, false
	}
	switch field {
	case "name":
		return u.Name, u.Name != ""
	case "domain":
		return u.Domain, u.Domain != ""
	case "id":
		return u.ID, u.ID != ""
	default:
		return nil, false
	}
}

func getHostSubfield(h *common.HostFields, field string) (interface{}, bool) {
	if h == nil {
		return nil, false
	}
	parts := strings.SplitN(field, ".", 2)
	switch parts[0] {
	case "name":
		return h.Name, h.Name != ""
	case "ip":
		if len(h.IP) > 0 {
			return h.IP, true
		}
		return nil, false
	case "os":
		if h.OS == nil {
			return nil, false
		}
		if len(parts) < 2 {
			return nil, false
		}
		switch parts[1] {
		case "name":
			return h.OS.Name, h.OS.Name != ""
		case "platform":
			return h.OS.Platform, h.OS.Platform != ""
		case "version":
			return h.OS.Version, h.OS.Version != ""
		default:
			return nil, false
		}
	default:
		return nil, false
	}
}

func getFileSubfield(f *common.FileFields, field string) (interface{}, bool) {
	if f == nil {
		return nil, false
	}
	parts := strings.SplitN(field, ".", 2)
	switch parts[0] {
	case "name":
		return f.Name, f.Name != ""
	case "path":
		return f.Path, f.Path != ""
	case "size":
		return f.Size, true
	case "hash":
		if f.Hash == nil {
			return nil, false
		}
		if len(parts) < 2 {
			return nil, false
		}
		switch parts[1] {
		case "md5":
			return f.Hash.MD5, f.Hash.MD5 != ""
		case "sha1":
			return f.Hash.SHA1, f.Hash.SHA1 != ""
		case "sha256":
			return f.Hash.SHA256, f.Hash.SHA256 != ""
		default:
			return nil, false
		}
	default:
		return nil, false
	}
}

func getRegistrySubfield(r *common.RegistryFields, field string) (interface{}, bool) {
	if r == nil {
		return nil, false
	}
	parts := strings.SplitN(field, ".", 2)
	switch parts[0] {
	case "key":
		return r.Key, r.Key != ""
	case "value":
		return r.Value, r.Value != ""
	case "data":
		if r.Data == nil {
			return nil, false
		}
		if len(parts) < 2 {
			return nil, false
		}
		switch parts[1] {
		case "type":
			return r.Data.Type, r.Data.Type != ""
		case "strings":
			if len(r.Data.Strings) > 0 {
				return r.Data.Strings, true
			}
			return nil, false
		default:
			return nil, false
		}
	default:
		return nil, false
	}
}

func getNetworkSubfield(n *common.NetworkFields, field string) (interface{}, bool) {
	if n == nil {
		return nil, false
	}
	switch field {
	case "protocol":
		return n.Protocol, n.Protocol != ""
	case "direction":
		return n.Direction, n.Direction != ""
	case "bytes":
		return n.Bytes, true
	case "transport":
		return n.Transport, n.Transport != ""
	case "packets":
		return n.Packets, true
	case "community_id":
		return n.CommunityID, n.CommunityID != ""
	default:
		return nil, false
	}
}

func getThreatSubfield(t *common.ThreatFields, field string) (interface{}, bool) {
	if t == nil {
		return nil, false
	}
	// threat.technique is a slice — return as-is.
	if field == "technique" {
		if len(t.Technique) > 0 {
			return t.Technique, true
		}
		return nil, false
	}
	return nil, false
}

func getDLPSubfield(d *common.DLPFields, field string) (interface{}, bool) {
	if d == nil {
		return nil, false
	}
	parts := strings.SplitN(field, ".", 2)
	switch parts[0] {
	case "classification":
		return d.Classification, d.Classification != ""
	case "channel":
		return d.Channel, d.Channel != ""
	case "policy":
		if d.Policy == nil {
			return nil, false
		}
		if len(parts) < 2 {
			return nil, false
		}
		switch parts[1] {
		case "name":
			return d.Policy.Name, d.Policy.Name != ""
		case "action":
			return d.Policy.Action, d.Policy.Action != ""
		default:
			return nil, false
		}
	default:
		return nil, false
	}
}

func getAVSubfield(a *common.AVFields, field string) (interface{}, bool) {
	if a == nil {
		return nil, false
	}
	parts := strings.SplitN(field, ".", 2)
	switch parts[0] {
	case "action":
		return a.Action, a.Action != ""
	case "scan":
		if a.Scan == nil {
			return nil, false
		}
		if len(parts) < 2 {
			return nil, false
		}
		switch parts[1] {
		case "result":
			return a.Scan.Result, a.Scan.Result != ""
		case "engine":
			return a.Scan.Engine, a.Scan.Engine != ""
		default:
			return nil, false
		}
	case "signature":
		if a.Signature == nil {
			return nil, false
		}
		if len(parts) < 2 {
			return nil, false
		}
		switch parts[1] {
		case "name":
			return a.Signature.Name, a.Signature.Name != ""
		default:
			return nil, false
		}
	default:
		return nil, false
	}
}

func getDNSSubfield(d *common.DNSFields, field string) (interface{}, bool) {
	if d == nil {
		return nil, false
	}
	parts := strings.SplitN(field, ".", 2)
	switch parts[0] {
	case "response_code":
		return d.ResponseCode, d.ResponseCode != ""
	case "header_flags":
		if len(d.HeaderFlags) > 0 {
			return d.HeaderFlags, true
		}
		return nil, false
	case "question":
		if d.Question == nil {
			return nil, false
		}
		if len(parts) < 2 {
			return nil, false
		}
		switch parts[1] {
		case "name":
			return d.Question.Name, d.Question.Name != ""
		case "type":
			return d.Question.Type, d.Question.Type != ""
		default:
			return nil, false
		}
	default:
		return nil, false
	}
}

func getHTTPSubfield(h *common.HTTPFields, field string) (interface{}, bool) {
	if h == nil {
		return nil, false
	}
	parts := strings.SplitN(field, ".", 2)
	switch parts[0] {
	case "request":
		if h.Request == nil {
			return nil, false
		}
		if len(parts) < 2 {
			return nil, false
		}
		switch parts[1] {
		case "method":
			return h.Request.Method, h.Request.Method != ""
		default:
			return nil, false
		}
	case "response":
		if h.Response == nil {
			return nil, false
		}
		if len(parts) < 2 {
			return nil, false
		}
		rParts := strings.SplitN(parts[1], ".", 2)
		switch rParts[0] {
		case "status_code":
			return h.Response.StatusCode, true
		case "body":
			if h.Response.Body == nil {
				return nil, false
			}
			if len(rParts) < 2 {
				return nil, false
			}
			if rParts[1] == "bytes" {
				return h.Response.Body.Bytes, true
			}
			return nil, false
		default:
			return nil, false
		}
	default:
		return nil, false
	}
}

func getTLSSubfield(t *common.TLSFields, field string) (interface{}, bool) {
	if t == nil {
		return nil, false
	}
	parts := strings.SplitN(field, ".", 2)
	switch parts[0] {
	case "version":
		return t.Version, t.Version != ""
	case "cipher":
		return t.Cipher, t.Cipher != ""
	case "client":
		if t.Client == nil {
			return nil, false
		}
		if len(parts) < 2 {
			return nil, false
		}
		switch parts[1] {
		case "ja3":
			return t.Client.JA3, t.Client.JA3 != ""
		case "ja4":
			return t.Client.JA4, t.Client.JA4 != ""
		case "server_name":
			return t.Client.ServerName, t.Client.ServerName != ""
		default:
			return nil, false
		}
	case "server":
		if t.Server == nil {
			return nil, false
		}
		if len(parts) < 2 {
			return nil, false
		}
		switch parts[1] {
		case "ja3s":
			return t.Server.JA3S, t.Server.JA3S != ""
		case "ja4s":
			return t.Server.JA4S, t.Server.JA4S != ""
		default:
			return nil, false
		}
	default:
		return nil, false
	}
}

func getURLSubfield(u *common.URLFields, field string) (interface{}, bool) {
	if u == nil {
		return nil, false
	}
	switch field {
	case "full":
		return u.Full, u.Full != ""
	default:
		return nil, false
	}
}

func getUserAgentSubfield(ua *common.UserAgentFields, field string) (interface{}, bool) {
	if ua == nil {
		return nil, false
	}
	switch field {
	case "original":
		return ua.Original, ua.Original != ""
	default:
		return nil, false
	}
}

func getSMBSubfield(s *common.SMBFields, field string) (interface{}, bool) {
	if s == nil {
		return nil, false
	}
	switch field {
	case "version":
		return s.Version, s.Version != ""
	case "action":
		return s.Action, s.Action != ""
	case "filename":
		return s.Filename, s.Filename != ""
	case "path":
		return s.Path, s.Path != ""
	case "domain":
		return s.Domain, s.Domain != ""
	case "username":
		return s.Username, s.Username != ""
	default:
		return nil, false
	}
}

func getKerberosSubfield(k *common.KerberosFields, field string) (interface{}, bool) {
	if k == nil {
		return nil, false
	}
	switch field {
	case "request_type":
		return k.RequestType, k.RequestType != ""
	case "client":
		return k.Client, k.Client != ""
	case "service":
		return k.Service, k.Service != ""
	case "cipher":
		return k.Cipher, k.Cipher != ""
	case "success":
		if k.Success != nil {
			return *k.Success, true
		}
		return nil, false
	case "error_code":
		return k.ErrorCode, k.ErrorCode != ""
	default:
		return nil, false
	}
}

func getSSHSubfield(s *common.SSHFields, field string) (interface{}, bool) {
	if s == nil {
		return nil, false
	}
	switch field {
	case "client":
		return s.Client, s.Client != ""
	case "server":
		return s.Server, s.Server != ""
	case "hassh":
		return s.HASSH, s.HASSH != ""
	case "hassh_server":
		return s.HASSHServer, s.HASSHServer != ""
	default:
		return nil, false
	}
}

func getNDRSubfield(n *common.NDRFields, field string) (interface{}, bool) {
	if n == nil {
		return nil, false
	}
	parts := strings.SplitN(field, ".", 2)
	switch parts[0] {
	case "detection":
		if n.Detection == nil {
			return nil, false
		}
		if len(parts) < 2 {
			return nil, false
		}
		switch parts[1] {
		case "name":
			return n.Detection.Name, n.Detection.Name != ""
		case "severity":
			return n.Detection.Severity, true
		case "certainty":
			return n.Detection.Certainty, true
		case "category":
			return n.Detection.Category, n.Detection.Category != ""
		case "pcap_ref":
			return n.Detection.PcapRef, n.Detection.PcapRef != ""
		default:
			return nil, false
		}
	case "host_score":
		if n.HostScore == nil {
			return nil, false
		}
		if len(parts) < 2 {
			return nil, false
		}
		switch parts[1] {
		case "threat":
			return n.HostScore.Threat, true
		case "certainty":
			return n.HostScore.Certainty, true
		case "quadrant":
			return n.HostScore.Quadrant, n.HostScore.Quadrant != ""
		default:
			return nil, false
		}
	case "beacon":
		if n.Beacon == nil {
			return nil, false
		}
		if len(parts) < 2 {
			return nil, false
		}
		switch parts[1] {
		case "interval_mean":
			return n.Beacon.IntervalMean, true
		case "interval_stddev":
			return n.Beacon.IntervalStddev, true
		default:
			return nil, false
		}
	case "session":
		if n.Session == nil {
			return nil, false
		}
		if len(parts) < 2 {
			return nil, false
		}
		switch parts[1] {
		case "conn_state":
			return n.Session.ConnState, n.Session.ConnState != ""
		case "community_id":
			return n.Session.CommunityID, n.Session.CommunityID != ""
		case "duration":
			return n.Session.Duration, true
		case "bytes_orig", "bytes_sent":
			return n.Session.BytesOrig, true
		case "bytes_resp", "bytes_recv":
			return n.Session.BytesResp, true
		case "packets_orig", "packets_sent":
			return n.Session.PacketsOrig, true
		case "packets_resp", "packets_recv":
			return n.Session.PacketsResp, true
		default:
			return nil, false
		}
	default:
		return nil, false
	}
}

func getObserverSubfield(o *common.ObserverFields, field string) (interface{}, bool) {
	if o == nil {
		return nil, false
	}
	parts := strings.SplitN(field, ".", 2)
	switch parts[0] {
	case "name":
		return o.Name, o.Name != ""
	case "type":
		return o.Type, o.Type != ""
	case "ingress":
		if o.Ingress == nil {
			return nil, false
		}
		if len(parts) < 2 {
			return nil, false
		}
		if parts[1] == "name" {
			return o.Ingress.Name, o.Ingress.Name != ""
		}
		return nil, false
	case "egress":
		if o.Egress == nil {
			return nil, false
		}
		if len(parts) < 2 {
			return nil, false
		}
		if parts[1] == "name" {
			return o.Egress.Name, o.Egress.Name != ""
		}
		return nil, false
	default:
		return nil, false
	}
}

func getLogSubfield(l *common.LogFields, field string) (interface{}, bool) {
	if l == nil {
		return nil, false
	}
	parts := strings.SplitN(field, ".", 2)
	if parts[0] != "syslog" || l.Syslog == nil || len(parts) < 2 {
		return nil, false
	}
	sysParts := strings.SplitN(parts[1], ".", 2)
	switch sysParts[0] {
	case "facility":
		if l.Syslog.Facility == nil {
			return nil, false
		}
		if len(sysParts) < 2 {
			return nil, false
		}
		switch sysParts[1] {
		case "code":
			return l.Syslog.Facility.Code, true
		case "name":
			return l.Syslog.Facility.Name, l.Syslog.Facility.Name != ""
		default:
			return nil, false
		}
	case "severity":
		if l.Syslog.Severity == nil {
			return nil, false
		}
		if len(sysParts) < 2 {
			return nil, false
		}
		switch sysParts[1] {
		case "code":
			return l.Syslog.Severity.Code, true
		case "name":
			return l.Syslog.Severity.Name, l.Syslog.Severity.Name != ""
		default:
			return nil, false
		}
	default:
		return nil, false
	}
}

func getRuleSubfield(r *common.RuleFields, field string) (interface{}, bool) {
	if r == nil {
		return nil, false
	}
	switch field {
	case "id":
		return r.ID, r.ID != ""
	case "name":
		return r.Name, r.Name != ""
	case "description":
		return r.Description, r.Description != ""
	case "category":
		return r.Category, r.Category != ""
	case "ruleset":
		return r.Ruleset, r.Ruleset != ""
	case "severity":
		return r.Severity, r.Severity != ""
	case "tags":
		if len(r.Tags) > 0 {
			return r.Tags, true
		}
		return nil, false
	case "reference":
		return r.Reference, r.Reference != ""
	case "author":
		return r.Author, r.Author != ""
	default:
		return nil, false
	}
}

// --- Condition AST ---

// ConditionExpr is the interface for condition AST nodes.
type ConditionExpr interface {
	Eval(selections map[string]bool) bool
}

// ConditionRef references a named selection.
type ConditionRef struct {
	Name string
}

func (c *ConditionRef) Eval(selections map[string]bool) bool {
	return selections[c.Name]
}

// ConditionNot negates a sub-expression.
type ConditionNot struct {
	Expr ConditionExpr
}

func (c *ConditionNot) Eval(selections map[string]bool) bool {
	return !c.Expr.Eval(selections)
}

// ConditionAnd requires both sub-expressions to be true.
type ConditionAnd struct {
	Left, Right ConditionExpr
}

func (c *ConditionAnd) Eval(selections map[string]bool) bool {
	return c.Left.Eval(selections) && c.Right.Eval(selections)
}

// ConditionOr requires either sub-expression to be true.
type ConditionOr struct {
	Left, Right ConditionExpr
}

func (c *ConditionOr) Eval(selections map[string]bool) bool {
	return c.Left.Eval(selections) || c.Right.Eval(selections)
}

// --- Condition Parser (recursive descent) ---

// parseCondition parses a Sigma condition string into an AST.
// Supports: selection references, "and", "or", "not", parentheses.
func parseCondition(condition string) (ConditionExpr, error) {
	tokens := tokenizeCondition(condition)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty condition")
	}
	p := &condParser{tokens: tokens}
	expr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.tokens) {
		return nil, fmt.Errorf("unexpected token %q at position %d", p.tokens[p.pos], p.pos)
	}
	return expr, nil
}

// tokenizeCondition splits a condition string into tokens.
func tokenizeCondition(condition string) []string {
	var tokens []string
	current := ""
	for _, ch := range condition {
		switch {
		case ch == '(' || ch == ')':
			if current != "" {
				tokens = append(tokens, current)
				current = ""
			}
			tokens = append(tokens, string(ch))
		case ch == ' ' || ch == '\t':
			if current != "" {
				tokens = append(tokens, current)
				current = ""
			}
		default:
			current += string(ch)
		}
	}
	if current != "" {
		tokens = append(tokens, current)
	}
	return tokens
}

type condParser struct {
	tokens []string
	pos    int
}

func (p *condParser) peek() string {
	if p.pos >= len(p.tokens) {
		return ""
	}
	return p.tokens[p.pos]
}

func (p *condParser) advance() string {
	tok := p.peek()
	p.pos++
	return tok
}

// parseOr handles: expr ("or" expr)*
func (p *condParser) parseOr() (ConditionExpr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "or") {
		p.advance()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &ConditionOr{Left: left, Right: right}
	}
	return left, nil
}

// parseAnd handles: expr ("and" expr)*
func (p *condParser) parseAnd() (ConditionExpr, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for strings.EqualFold(p.peek(), "and") {
		p.advance()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &ConditionAnd{Left: left, Right: right}
	}
	return left, nil
}

// parseNot handles: "not" expr | primary
func (p *condParser) parseNot() (ConditionExpr, error) {
	if strings.EqualFold(p.peek(), "not") {
		p.advance()
		expr, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return &ConditionNot{Expr: expr}, nil
	}
	return p.parsePrimary()
}

// parsePrimary handles: "(" expr ")" | selection_ref
func (p *condParser) parsePrimary() (ConditionExpr, error) {
	tok := p.peek()
	if tok == "" {
		return nil, fmt.Errorf("unexpected end of condition")
	}

	if tok == "(" {
		p.advance()
		expr, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek() != ")" {
			return nil, fmt.Errorf("expected ')', got %q", p.peek())
		}
		p.advance()
		return expr, nil
	}

	// Check for unsupported "1 of" / "all of" syntax.
	lower := strings.ToLower(tok)
	if lower == "1" || lower == "all" {
		nextTok := ""
		if p.pos+1 < len(p.tokens) {
			nextTok = strings.ToLower(p.tokens[p.pos+1])
		}
		if nextTok == "of" {
			return nil, fmt.Errorf("%q of ... syntax is not supported", tok)
		}
	}

	// Must be a selection reference.
	p.advance()
	return &ConditionRef{Name: tok}, nil
}

func getWinEvtSubfield(w *common.WinEvtFields, field string) (interface{}, bool) {
	if w == nil {
		return nil, false
	}
	switch field {
	case "channel":
		return w.Channel, w.Channel != ""
	case "provider":
		return w.Provider, w.Provider != ""
	case "event_id":
		return w.EventID, true
	default:
		return nil, false
	}
}
