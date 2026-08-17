# Pinned validation catalogs

`azure-mcp-2.0.5-tool-catalog.json` binds the deployment to three independently inspectable
artifacts:

- npm package `@azure/mcp@2.0.5` and its immutable distribution SHA-1;
- MCR image manifest/config digests and the image's
  `com.azure.dev.image.build.sourceversion` label; and
- the exact Microsoft MCP source revision named by that OCI label.

At revision `2712e19ddf1c55f8e73ead8fb671915ec92801cc`, the changelog declares 2.0.5,
`ServiceStartCommand.cs` calls parameterless `app.MapMcp()` (root route), and the command factory
uses `_`-joined command paths as `Name = fullName` runtime MCP tool names.

## Deterministic catalog regeneration

The top-level Azure MCP command response contains a nondeterministic `duration`; it must not be
hashed. Regenerate the hash from `results` only:

```powershell
npx -y @azure/mcp@2.0.5 tools list 2>$null |
  & .venv\Scripts\python.exe -c 'import hashlib,json,sys; p=json.load(sys.stdin); c=json.dumps(p["results"],sort_keys=True,separators=(",",":"),ensure_ascii=False).encode(); print(len(p["results"]),hashlib.sha256(c).hexdigest())'
```

The expected output is:

```text
235 032b52ae4214b9df410182292b2bf0a82f9a84eec7b64cc5c8c40f726c4d4a0c
```

Run the command at least twice and require identical output. Regenerate selected records directly
from the same response; do not manually infer runtime names from CLI examples.
