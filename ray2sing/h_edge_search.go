package ray2sing

import (
	"encoding/json"
	"reflect"
	"strings"

	"github.com/sagernet/sing/common/json/badoption"
)

// The public ray2sing parser is also consumed by older hiddify-sing-box engines.
// Upstream's edge-search option structs are not present in all engine revisions.
// Reflection makes the *new* URL parameters available when the engine supports
// them, without breaking builds or changing the caller's public Go API.
func setOptionalField(target reflect.Value, name string, value any) {
	if !target.IsValid() || target.Kind() != reflect.Struct {
		return
	}
	field := target.FieldByName(name)
	if !field.IsValid() || !field.CanSet() {
		return
	}
	in := reflect.ValueOf(value)
	if !in.IsValid() {
		return
	}
	if in.Type().AssignableTo(field.Type()) {
		field.Set(in)
	} else if in.Type().ConvertibleTo(field.Type()) {
		field.Set(in.Convert(field.Type()))
	}
}

func setOptionalStringList(target reflect.Value, name, value string) {
	if value == "" || !target.IsValid() {
		return
	}
	field := target.FieldByName(name)
	if !field.IsValid() || !field.CanSet() {
		return
	}
	copy := reflect.New(field.Type())
	if json.Unmarshal(jsonStringList(value), copy.Interface()) == nil {
		field.Set(copy.Elem())
	}
}

func setEdgeSearchOptions(target any, param func(...string) string) {
	v := reflect.ValueOf(target)
	if !v.IsValid() || v.Kind() != reflect.Ptr || v.IsNil() {
		return
	}
	v = v.Elem()
	if embedded := v.FieldByName("EdgeSearchOptions"); embedded.IsValid() && embedded.Kind() == reflect.Struct {
		v = embedded
	}
	timeout := param("search_timeout")
	var duration badoption.Duration
	switch strings.ToLower(timeout) {
	case "deep", "unlimited", "none", "inf", "infinite":
		duration = badoption.Duration(-1)
	default:
		duration = warpDuration(timeout)
	}
	setOptionalField(v, "SearchTimeout", duration)
	setOptionalField(v, "DeepConcurrency", toInt(param("deep_concurrency")))
	setOptionalField(v, "BlockBitsIPv4", toInt(param("block_bits_ipv4", "block_bits_v4")))
	setOptionalField(v, "BlockBitsIPv6", toInt(param("block_bits_ipv6", "block_bits_v6")))
}

// applyPsiphonScanner has no effect with older engines that have no Scanner
// field. Once the sibling engine exposes a scanner the same links work
// without requiring a new version of this module.
func applyPsiphonScanner(options any, params map[string]string) {
	param := func(keys ...string) string { return getOneOfN(params, "", keys...) }
	keys := []string{
		"scanner", "scan", "scan_sets", "scan_cidrs", "scan_sni",
		"scan_candidates", "scan_count", "scan_concurrency", "scan_timeout", "max_rtt",
		"search_timeout", "deep_concurrency", "block_bits_ipv4", "block_bits_v4",
		"block_bits_ipv6", "block_bits_v6",
	}
	enabledByLink := false
	for _, key := range keys {
		if _, ok := params[normalizeStr(key)]; ok {
			enabledByLink = true
			break
		}
	}
	if !enabledByLink {
		return
	}
	v := reflect.ValueOf(options)
	if !v.IsValid() || v.Kind() != reflect.Ptr || v.IsNil() {
		return
	}
	field := v.Elem().FieldByName("Scanner")
	if !field.IsValid() || !field.CanSet() || field.Kind() != reflect.Ptr ||
		field.Type().Elem().Kind() != reflect.Struct {
		return
	}
	scanner := reflect.New(field.Type().Elem())
	o := scanner.Elem()
	setOptionalStringList(o, "Sets", param("scan_sets"))
	setOptionalStringList(o, "ServerNames", param("scan_sni"))
	setOptionalStringList(o, "CIDRs", param("scan_cidrs"))
	setOptionalField(o, "Candidates", toInt(param("scan_candidates")))
	setOptionalField(o, "Count", toInt(param("scan_count")))
	setOptionalField(o, "Concurrency", toInt(param("scan_concurrency")))
	setOptionalField(o, "Timeout", warpDuration(param("scan_timeout")))
	setOptionalField(o, "MaxRTT", warpDuration(param("max_rtt", "scan_max_rtt")))
	if value := param("scanner", "scan"); value != "" {
		enabled := toBool(value, true)
		setOptionalField(o, "Enabled", &enabled)
	}
	setEdgeSearchOptions(scanner.Interface(), param)
	field.Set(scanner)
}
