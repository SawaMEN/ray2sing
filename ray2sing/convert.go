package ray2sing

import (
	"context"
	"fmt"
	"net/url"

	"strconv"
	"strings"

	_ "github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

var configTypes = map[string]ParserFunc{
	"vmess://":       VmessSingbox,
	"vless://":       VlessSingbox,
	"trojan://":      TrojanSingbox,
	"svmess://":      VmessSingbox,
	"svless://":      VlessSingbox,
	"strojan://":     TrojanSingbox,
	"ss://":          ShadowsocksSingbox,
	"tuic://":        TuicSingbox,
	"hysteria://":    HysteriaSingbox,
	"hysteria2://":   Hysteria2Singbox,
	"hy2://":         Hysteria2Singbox,
	"ssh://":         SSHSingbox,
	"naive://":       NaiveSingbox,
	"naive+https://": NaiveSingbox,
	"naive+quic://":  NaiveSingbox,
	"anytls://":      AnyTLSSingbox,
	"snell://":       SnellSingbox,

	"ssconf://":      BeepassSingbox,
	"direct://":      DirectSingbox,
	"socks://":       SocksSingbox,
	"phttp://":       HttpSingbox,
	"phttps://":      HttpsSingbox,
	"http://":        HttpSingbox,
	"https://":       HttpsSingbox,
	"xvmess://":      VmessXray,
	"xvless://":      VlessXray,
	"xtrojan://":     TrojanXray,
	"xdirect://":     DirectXray,
	"mieru://":       MieruSingbox,
	"mierus://":      MieruSingbox,
	"psiphon://":     PsiphonSingbox,
	"dnstt://":       DnsttSingbox,
	"masterdns://":   MasterdnsSingbox,
	"soar://":        SoarSingbox,
	"slipnet://":     SlipnetSingbox,
	"slipnet-enc://": SlipnetSingbox,
	"dnst://":        DnstSingbox,
	"masque://":      MasqueSingbox,
}
var endpointParsers = map[string]EndpointParserFunc{
	"wg://":        AWGSingbox,
	"wireguard://": AWGSingbox,
	"warp://":      WarpSingbox,
	"awg://":       AWGSingbox,
	"[Interface]":  AWGSingboxTxt,
}
var xrayConfigTypes = map[string]ParserFunc{
	"vmess://":  VmessXray,
	"vless://":  VlessXray,
	"trojan://": TrojanXray,
	"direct://": DirectXray,
}

type OutEnd struct {
	outbound *T.Outbound
	endpoint *T.Endpoint
}

func processSingleConfig(config string, useXrayWhenPossible bool) (outend *OutEnd, err error) {
	defer func() {
		if r := recover(); r != nil {
			outend = nil
			err = fmt.Errorf("panic while parsing configuration (%T)", r)
		}
	}()
	// configDecoded := decodeUrlBase64IfNeeded(config)
	outend = &OutEnd{}
	if false && (useXrayWhenPossible || strings.Contains(config, "&core=xray")) {
		for k, v := range xrayConfigTypes {
			if strings.HasPrefix(config, k) {
				outend.outbound, err = v(config)
				break
			}
		}
	}
	if strings.HasPrefix(config, "masque://") { // a WARP one is a warp endpoint, see MasqueLinkSingbox
		outend.outbound, outend.endpoint, err = MasqueLinkSingbox(config)
	} else if outend.outbound == nil {
		for k, v := range configTypes {
			if strings.HasPrefix(config, k) {
				outend.outbound, err = v(config)
				break
			}
		}
		for k, v := range endpointParsers {
			if strings.HasPrefix(config, k) {
				outend.endpoint, err = v(config)
				break
			}
		}
	}

	if err != nil {
		return nil, err
	}
	if outend.endpoint == nil && outend.outbound == nil {
		return nil, E.New("Not supported config type")
	}
	if err := applyFinalMask(config, outend); err != nil {
		return nil, err
	}
	if outend.outbound != nil && outend.outbound.Tag == "" {
		outend.outbound.Tag = outend.outbound.Type
	}
	if outend.endpoint != nil && outend.endpoint.Tag == "" {
		outend.endpoint.Tag = outend.endpoint.Type
	}

	// json.MarshalIndent(configSingbox, "", "  ")
	return outend, nil
}

func GenerateConfigLite(input string, useXrayWhenPossible bool) (*option.Options, error) {
	configArray := expandDecodedConfig(input)

	var outbounds []T.Outbound
	var endpoints []T.Endpoint
	var declaredIPv6 map[string]bool // ipv6=1 or ipv6=0, indexed by final tag
	counter := 0
	failedConfigs := 0

	for _, config := range configArray {
		if len(config) < 5 || config[0] == '#' || config[0] == '/' {
			continue
		}
		config = unescapeHTMLAmpersand(config)

		// A detour chain is atomic: never install only its inner hops when
		// an outer hop is malformed. That can unintentionally bypass the
		// intended proxy, and its IPv6 metadata must not survive either.
		var chainOutbounds []T.Outbound
		var chainEndpoints []T.Endpoint
		var chainIPv6 map[string]bool
		detourTag := ""
		nextCounter := counter
		validChain := true

		chains := strings.Split(expandLinks(config), " -> ")
		for i := len(chains) - 1; i >= 0; i-- {
			chain, _ := decodeBase64IfNeeded(strings.TrimSpace(chains[i]))
			if isSubscriptionInfoEntry(chain) {
				continue
			}
			outend, err := processSingleConfig(chain, useXrayWhenPossible)
			if err != nil {
				// Do not log the original URI (it can contain credentials,
				// WireGuard private keys, or tokens). Continue with other
				// independent subscription entries.
				failedConfigs++
				validChain = false
				break
			}

			suffix := " § " + strconv.Itoa(nextCounter)
			if outend.outbound != nil {
				outend.outbound.Tag += suffix
				if carried, declared := ipv6Hint(chain); declared {
					if chainIPv6 == nil {
						chainIPv6 = make(map[string]bool)
					}
					chainIPv6[outend.outbound.Tag] = carried
				}
				if dialerOpt, ok := outend.outbound.Options.(T.DialerOptionsWrapper); ok {
					d := dialerOpt.TakeDialerOptions()
					d.Detour = detourTag
					dialerOpt.ReplaceDialerOptions(d)
				}
				if detourTag != "" {
					disableMasqueScanner(outend.outbound)
				}
				detourTag = outend.outbound.Tag
				chainOutbounds = append(chainOutbounds, *outend.outbound)
			} else {
				outend.endpoint.Tag += suffix
				if carried, declared := ipv6Hint(chain); declared {
					if chainIPv6 == nil {
						chainIPv6 = make(map[string]bool)
					}
					chainIPv6[outend.endpoint.Tag] = carried
				}
				if dialerOpt, ok := outend.endpoint.Options.(T.DialerOptionsWrapper); ok {
					d := dialerOpt.TakeDialerOptions()
					d.Detour = detourTag
					dialerOpt.ReplaceDialerOptions(d)
				}
				if detourTag != "" {
					warpBehindDetour(outend.endpoint)
				}
				detourTag = outend.endpoint.Tag
				chainEndpoints = append(chainEndpoints, *outend.endpoint)
			}
			nextCounter++
		}

		if !validChain {
			continue
		}
		outbounds = append(outbounds, chainOutbounds...)
		endpoints = append(endpoints, chainEndpoints...)
		if len(chainIPv6) > 0 {
			if declaredIPv6 == nil {
				declaredIPv6 = make(map[string]bool)
			}
			for tag, carried := range chainIPv6 {
				declaredIPv6[tag] = carried
			}
		}
		counter = nextCounter
	}

	if len(outbounds) == 0 && len(endpoints) == 0 {
		if failedConfigs > 0 {
			return nil, fmt.Errorf("No outbounds found: %d invalid configuration(s)", failedConfigs)
		}
		return nil, E.New("No outbounds found")
	}

	fullConfig := T.Options{
		Outbounds: outbounds,
		Endpoints: endpoints,
	}
	declareIPv6(&fullConfig, declaredIPv6)
	return &fullConfig, nil
}

func Ray2Singbox(ctx context.Context, configs string, useXrayWhenPossible bool) (out []byte, err error) {
	convertedData, err := Ray2SingboxOptions(ctx, configs, useXrayWhenPossible)
	if err != nil {
		return nil, err
	}
	// err = libbox.CheckConfigOptions(convertedData)
	// if err != nil {
	// 	return nil, err
	// }
	return convertedData.MarshalJSONContext(ctx)
}
func Ray2SingboxOptions(ctx context.Context, configs string, useXrayWhenPossible bool) (out *option.Options, err error) {
	defer func() {
		if r := recover(); r != nil {
			out = nil
			err = fmt.Errorf("panic while parsing configuration (%T)", r)

		}
	}()

	configs, _ = decodeBase64IfNeeded(configs)

	convertedData, err := GenerateConfigLite(configs, useXrayWhenPossible)
	return convertedData, err
}

// isSubscriptionInfoEntry reports Hiddify panel entries that only show the subscription's usage and
// expiry in their name (sni=fake_ip_for_sub_link); they are not servers, and the same data comes in
// the subscription-userinfo header.
func isSubscriptionInfoEntry(config string) bool {
	u, err := url.Parse(config)
	return err == nil && u.Query().Get("sni") == "fake_ip_for_sub_link"
}
