package ray2sing

import "testing"

func TestParseURLRejectsInvalidPorts(t *testing.T) {
	for _, input := range []string{
		"hysteria2://secret@example.com:0#zero",
		"hysteria2://secret@example.com:65536#overflow",
		"hysteria2://secret@example.com:70000-70001#hop-overflow",
		"hysteria2://secret@example.com:443,6000-5000#reversed-range",
		"hysteria2://secret@example.com:443,0-100#zero-in-range",
	} {
		if parsed, err := ParseUrl(input, 443); err == nil {
			t.Errorf("%q: expected invalid port error, got %+v", input, parsed)
		}
	}
}

func TestParseURLValidHoppingPorts(t *testing.T) {
	parsed, err := ParseUrl("hysteria2://secret@example.com:443,20000-30000,8443#hop", 443)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Port != 443 || len(parsed.PortRanges) != 3 ||
		parsed.PortRanges[0] != "443:443" ||
		parsed.PortRanges[1] != "20000:30000" ||
		parsed.PortRanges[2] != "8443:8443" {
		t.Fatalf("unexpected hopping ports: %+v", parsed)
	}
}
