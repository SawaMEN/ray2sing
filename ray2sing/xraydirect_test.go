package ray2sing

import (
	"testing"

	T "github.com/sagernet/sing-box/option"
)

func TestXrayDirectFragmentParameters(t *testing.T) {
	out, err := DirectXray("xdirect://example.com:443?fragment=tlshello,10-20,1-2#frag")
	if err != nil {
		t.Fatal(err)
	}
	opts, ok := out.Options.(*T.XrayOutboundOptions)
	if !ok || opts.XConfig == nil {
		t.Fatalf("expected Xray outbound, got %+v", out.Options)
	}
	config := *opts.XConfig
	settings, ok := config["settings"].(map[string]any)
	if !ok {
		t.Fatalf("missing Xray settings: %+v", config)
	}
	fragment, ok := settings["fragment"].(map[string]any)
	if !ok || fragment["packets"] != "tlshello" || fragment["length"] != "10-20" || fragment["interval"] != "1-2" {
		t.Fatalf("unexpected fragment settings: %+v", settings)
	}
}

func TestXrayDirectRejectsMalformedFragment(t *testing.T) {
	for _, value := range []string{"tlshello", "tlshello,10-20", "tlshello,,1-2"} {
		if result, err := DirectXray("xdirect://example.com:443?frg=" + value); err == nil {
			t.Errorf("%q: expected an error, got %+v", value, result)
		}
	}
}

func TestXrayDirectOmitsFragmentWhenAbsent(t *testing.T) {
	out, err := DirectXray("xdirect://example.com:443#plain")
	if err != nil {
		t.Fatal(err)
	}
	settings := (*out.Options.(*T.XrayOutboundOptions).XConfig)["settings"].(map[string]any)
	if _, exists := settings["fragment"]; exists {
		t.Fatalf("unexpected fragment: %+v", settings)
	}
}
