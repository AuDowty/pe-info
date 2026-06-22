# pe-info

Inspect PE/COFF binaries (Windows `.exe`/`.dll`). Cross-platform.

## Install

```
cargo install --git https://github.com/AuDowty/pe-info
```

## Use

```
pe-info headers  some.dll
pe-info sections some.dll
pe-info imports  some.dll
pe-info exports  some.dll
```

Add `--json` to any subcommand for machine-readable output:

```
pe-info imports some.dll --json | jq '.[] | .dll'
```

## License

MIT
