package ray2sing

import (
	"strings"
	"testing"

	T "github.com/sagernet/sing-box/option"
)

const testTrojanURL = "trojan://password@192.0.2.10:443?security=tls&sni=example.com&type=tcp#good"

func TestInvalidLinksDoNotLeakCredentials(t *testing.T) {
	secret := "SUPER_SECRET_PRIVATE_KEY"
	_, err := GenerateConfigLite("unsupported://"+secret, false)
	if err == nil {
		t.Fatal("expected an error for unsupported link")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked credentials: %v", err)
	}
	if !strings.Contains(err.Error(), "No outbounds found") {
		t.Fatalf("expected a useful failure reason, got: %v", err)
	}
}

func TestInvalidEntryDoesNotDiscardIndependentValidLinks(t *testing.T) {
	options, err := GenerateConfigLite("unsupported://secret\n"+testTrojanURL, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Outbounds) != 1 || options.Outbounds[0].Tag != "good § 0" {
		t.Fatalf("expected only the valid link, got %+v", options.Outbounds)
	}
}

func TestMalformedDetourChainIsNotPartiallyInstalled(t *testing.T) {
	// The inner hop is valid, but installing it alone would silently bypass
	// the user's explicitly selected outer hop.
	chain := "unsupported://secret -> " + testTrojanURL
	if options, err := GenerateConfigLite(chain, false); err == nil {
		t.Fatalf("malformed chain must fail, not install %+v", options)
	}

	options, err := GenerateConfigLite(chain+"\n"+testTrojanURL, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Outbounds) != 1 || options.Outbounds[0].Tag != "good § 0" {
		t.Fatalf("broken chain leaked an inner outbound: %+v", options.Outbounds)
	}
}

func TestValidDetourChainPreservesOrderAndDetour(t *testing.T) {
	outer := "trojan://outer@192.0.2.11:443?security=tls&sni=example.com&type=tcp#outer"
	inner := "trojan://inner@192.0.2.12:443?security=tls&sni=example.com&type=tcp#inner"
	options, err := GenerateConfigLite(outer+" -> "+inner, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Outbounds) != 2 ||
		options.Outbounds[0].Tag != "inner § 0" ||
		options.Outbounds[1].Tag != "outer § 1" {
		t.Fatalf("unexpected chain order: %+v", options.Outbounds)
	}
	dialer, ok := options.Outbounds[1].Options.(T.DialerOptionsWrapper)
	if !ok || dialer.TakeDialerOptions().Detour != "inner § 0" {
		t.Fatalf("outer hop did not detour through inner hop: %+v", options.Outbounds[1])
	}
}
