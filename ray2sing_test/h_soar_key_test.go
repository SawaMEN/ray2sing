package ray2sing_test

import (
	"encoding/base64"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	"github.com/sagernet/sing-box/option"
)

func TestSoarRawBase64LeadingPlus(t *testing.T) {
	key := make([]byte, 32)
	key[0] = 0xfb
	encoded := base64.StdEncoding.EncodeToString(key)
	out, err := ray2sing.SoarSingbox("soar://t.example.com?pk=" + encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got := out.Options.(*option.SoarOptions).PublicKey; got != encoded {
		t.Fatalf("key changed: %q != %q", got, encoded)
	}
}
