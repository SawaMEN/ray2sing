package ray2sing

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/json/badoption"
)

type testEdgeSearch struct {
	SearchTimeout   badoption.Duration
	DeepConcurrency int
	BlockBitsIPv4   int
	BlockBitsIPv6   int
}

type testOptionalScanner struct {
	EdgeSearchOptions testEdgeSearch
	Enabled           *bool
	Sets              []string
	ServerNames       []string
	CIDRs             []netip.Prefix
	Candidates        int
	Count             int
	Concurrency       int
	Timeout           badoption.Duration
	MaxRTT            badoption.Duration
}

type testOptionalPsiphon struct {
	Scanner *testOptionalScanner
}

func TestEdgeSearchOptionsWhenEngineSupportsThem(t *testing.T) {
	params := map[string]string{
		"searchtimeout": "300", "deepconcurrency": "48",
		"blockbitsipv4": "24", "blockbitsipv6": "56",
	}
	param := func(keys ...string) string { return getOneOfN(params, "", keys...) }
	scanner := &testOptionalScanner{}
	setEdgeSearchOptions(scanner, param)
	if time.Duration(scanner.EdgeSearchOptions.SearchTimeout) != 300*time.Second ||
		scanner.EdgeSearchOptions.DeepConcurrency != 48 || scanner.EdgeSearchOptions.BlockBitsIPv4 != 24 ||
		scanner.EdgeSearchOptions.BlockBitsIPv6 != 56 {
		t.Fatalf("search options not preserved: %+v", scanner)
	}
	params["searchtimeout"] = "deep"
	setEdgeSearchOptions(scanner, param)
	if scanner.EdgeSearchOptions.SearchTimeout >= 0 {
		t.Fatalf("expected unlimited search: %+v", scanner)
	}
}

func TestOptionalPsiphonScannerURLParameters(t *testing.T) {
	opts := &testOptionalPsiphon{}
	applyPsiphonScanner(opts, map[string]string{
		"scan": "true", "scansets": "fastly,akamai", "scancandidates": "3",
		"searchtimeout": "2h", "deepconcurrency": "64",
		"blockbitsipv4": "22", "scancidrs": "192.0.2.0/24",
	})
	scanner := opts.Scanner
	if scanner == nil || scanner.Enabled == nil || !*scanner.Enabled ||
		len(scanner.Sets) != 2 || scanner.Candidates != 3 ||
		scanner.EdgeSearchOptions.DeepConcurrency != 64 || scanner.EdgeSearchOptions.BlockBitsIPv4 != 22 ||
		time.Duration(scanner.EdgeSearchOptions.SearchTimeout) != 2*time.Hour ||
		len(scanner.CIDRs) != 1 {
		t.Fatalf("failed to read scanner parameters: %+v", scanner)
	}
}

func TestOptionalScannerAbsentInOlderEngine(t *testing.T) {
	withoutScanner := &struct{ Name string }{}
	applyPsiphonScanner(withoutScanner, map[string]string{"scancandidates": "3"})
	setEdgeSearchOptions(withoutScanner, func(...string) string { return "300" })
}
