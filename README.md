# ray2sing

Go library for converting V2Ray/Xray subscription links and WireGuard-family links into sing-box outbounds and endpoints. This fork is integrated with [SawaMEN/hiddify-sing-box](https://github.com/SawaMEN/hiddify-sing-box) and used by Hiddify-related projects.

## Compatibility

The Go module path is intentionally kept as `github.com/hiddify/ray2sing` for existing consumers. The `go.mod` file uses local `replace` directives pointing to `../hiddify-sing-box` and its native replacements: **clone both repositories into the same parent directory**. The CI workflow pins an exact compatible engine commit and uses the Go version specified in `go.mod`. Do not swap the module with upstream `github.com/sagernet/sing-box` without also adapting custom protocol options and running the full test suite.

```bash
git clone https://github.com/SawaMEN/hiddify-sing-box.git
git clone https://github.com/SawaMEN/ray2sing.git
cd ray2sing
go test -mod=readonly -race -ldflags=-checklinkname=0 ./...
```

For reproducible checks, consult [the CI workflow](.github/workflows/test.yml) for the exact engine commit. The fork-specific parser is not guaranteed to work with arbitrary newer sing-box releases.

## Usage

Convert a single share link:

```bash
go run . 'trojan://password@example.com:443?security=tls#proxy'
```

Convert several links, from a local file or stdin:

```bash
go run . -file links.txt
cat links.txt | go run .
```

The CLI writes only the converted JSON to stdout and errors to stderr. It makes no network requests to fetch an example subscription. Input from files/stdin is limited to 8 MiB. The library also exposes `ray2sing.Ray2Singbox`, `ray2sing.Ray2SingboxOptions`, and `ray2sing.GenerateConfigLite`.

## Parsing behavior

- Independent valid entries are retained if another subscription entry is invalid.
- A detour chain is atomic: if any hop fails, the whole chain is discarded. This prevents accidentally exposing a standalone inner proxy without the requested detour.
- A subscription that yields no valid entries returns an error. Raw links and secrets are never printed in conversion error diagnostics.
- Explicit invalid ports, out-of-range ports, and reversed port-hopping ranges are rejected.
- Unsupported URL schemes are skipped; they are not converted into approximate protocols.
- The `useXrayWhenPossible` argument is reserved; automatic selection of an Xray outbound is currently disabled in the parser. Explicit `xvless://`, `xvmess://`, and `xtrojan://` links still use the corresponding Xray parsers.

## Acknowledgements

- [sing-box](https://github.com/SagerNet/sing-box)
- [Hiddify](https://github.com/hiddify)
- [SingBoxer](https://github.com/yebekhe/SingBoxer)
- [v2box](https://github.com/SagerNet/v2box)
