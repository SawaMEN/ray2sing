package ray2sing

import (
	"fmt"
	"strings"

	T "github.com/sagernet/sing-box/option"
)

func DirectXray(vlessURL string) (*T.Outbound, error) {
	u, err := ParseUrl(vlessURL, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	// fmt.Println(u)
	// packetEncoding := decoded["packetencoding"]
	// if packetEncoding==""{
	// 	packetEncoding="xudp"
	// }
	fragment := getOneOfN(decoded, "", "frg", "fragment")
	settings := map[string]any{}
	if fragment != "" {
		parts := strings.Split(fragment, ",")
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return nil, fmt.Errorf("invalid Xray fragment: expected packets,length,interval")
		}
		settings["fragment"] = map[string]any{
			"packets":  parts[0],
			"length":   parts[1],
			"interval": parts[2],
		}
	}

	return makeXrayOptions(decoded, map[string]any{
		"protocol":       "freedom",
		"domainStrategy": "AsIs",
		"settings": settings,
		"streamSettings": map[string]any{
			"sockopt": map[string]any{
				"tcpNoDelay":       true,
				"tcpKeepAliveIdle": 100,
			},
		},
		"tag": u.Name,
	})
}

// func toInt32Range(s string) *conf.Int32Range {
// 	rngs, rnge, err := conf.ParseRangeString(s)
// 	if err != nil {
// 		return nil
// 	}
// 	return &conf.Int32Range{
// 		Left:  int32(rngs),
// 		Right: int32(rnge),
// 	}
// }

// func DirectXray(vlessURL string) (*T.Outbound, error) {
// 	u, err := ParseUrl(vlessURL, 443)
// 	if err != nil {
// 		return nil, err
// 	}
// 	decoded := u.Params
// 	// packetEncoding := decoded["packetencoding"]
// 	// if packetEncoding==""{
// 	// 	packetEncoding="xudp"
// 	// }
// 	frag, err := getOneOf(decoded, "frg", "fragment")
// 	fragdata := conf.Fragment{}
// 	if err != nil && frag != "" {
// 		frags := strings.Split(frag, ",")
// 		fragdata.Packets = frags[0]
// 		fragdata.Length = toInt32Range(frags[1])
// 		fragdata.Interval = toInt32Range(frags[2])
// 	}
// 	streamSettings := conf.StreamConfig{
// 		SocketSettings: &conf.SocketConfig{

// 			TCPKeepAliveIdle: 100,
// 		},
// 	}
// 	xout := conf.OutboundDetourConfig{
// 		Tag:           u.Name,
// 		Protocol:      "freedom",
// 		StreamSetting: &streamSettings,
// 		MuxSettings:   getMuxOptionsXray(decoded),
// 		Settings: marshalJSON(conf.FreedomConfig{
// 			Fragment: &fragdata,
// 		}),
// 	}
// 	return makeXrayOptions(decoded, &xout)
// }
