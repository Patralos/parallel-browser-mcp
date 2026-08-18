# parallel-browser-mcp

[![npm version](https://img.shields.io/npm/v/parallel-browser-mcp.svg)](https://www.npmjs.com/package/parallel-browser-mcp)
[![npm downloads](https://img.shields.io/npm/dt/parallel-browser-mcp.svg)](https://www.npmjs.com/package/parallel-browser-mcp)

`parallel-browser-mcp` is an MCP server for parallel browser automation. It exposes a numeric session model over MCP so one client can create and control multiple browser sessions at the same time across multiple browser providers.

Supported providers:
- `playwright` for local Chromium
- `browserbase` via `@browserbasehq/sdk`
- `anchor` via `anchorbrowser`
- `cloudflare` via Cloudflare Browser Run

Each browser session gets a numeric ID like `1`, `2`, `3`, and every `browser_*` tool accepts a `sessionId`.

## Features

- Multiple concurrent browser sessions in memory
- Provider abstraction shared across Browserbase, Anchor Browser, Cloudflare Browser Run, and local Playwright
- MCP session tools:
  - `start_session`
  - `close_session`
  - `close_all_sessions`
  - `get_sessions`
- Browser tools:
  - `browser_navigate`
  - `browser_go_back`
  - `browser_click`
  - `browser_fill`
  - `browser_fill_form`
  - `browser_screenshot`
  - `browser_snapshot`
  - `browser_hover`
  - `browser_drag`
  - `browser_select_option`
  - `browser_generate_locator`
  - `browser_get_page_structure`
  - `browser_evaluate`
  - `browser_keyboard_press`
  - `browser_keyboard_type`
  - `browser_mouse_move`
  - `browser_mouse_click_xy`
  - `browser_mouse_drag`
  - `browser_upload_file`
  - `browser_wait_for_selector`
  - `browser_wait_for_timeout`

## Quick Start

```bash
corepack pnpm install
corepack pnpm build
```

Run locally over stdio:

```bash
node dist/index.js
```

Run it as an npm package CLI:

```bash
npx parallel-browser-mcp@latest
```

## Configuration

Provider-specific settings are configured at the MCP server configuration level, not per tool call.

The server reads config in this order:
1. `BROWSER_MCP_CONFIG`
2. `BROWSER_MCP_CONFIG_PATH`
3. direct env defaults
4. built-in defaults

Recommended config shape:

```json
{
  "defaultProvider": "playwright",
  "providers": {
    "browserbase": {
      "projectId": "proj_123",
      "keepAlive": true
    },
    "anchor": {
      "recording": false
    },
    "playwright": {
      "launchOptions": {
        "headless": true
      },
      "useCloakBrowser": false
    }
  }
}
```

### Security policy: origin allowlist and upload directories

Like `launchOptions`, this is configured at the server level and is **not** reachable from any tool
argument, so a calling agent cannot widen its own scope.

```json
{
  "security": {
    "allowedOrigins": ["app.example.com", "*.api.example.com", "127.0.0.1:8080"],
    "blockedOrigins": ["admin.example.com"],
    "blockedSchemes": [],
    "allowedUploadDirectories": ["/srv/engagement/uploads"]
  }
}
```

Equivalent env vars (`;`-separated): `BROWSER_MCP_ALLOWED_ORIGINS`, `BROWSER_MCP_BLOCKED_ORIGINS`,
`BROWSER_MCP_BLOCKED_SCHEMES`, `BROWSER_MCP_ALLOWED_UPLOAD_DIRS`.

**Where it is enforced.** In the browser layer, not in tool arguments. `browser_evaluate` runs
arbitrary JavaScript in the page, so validating the `url` argument of `browser_navigate` would stop
nothing -- page script can set `location.href`, `fetch`, inject an iframe or call `window.open`. The
allowlist is therefore applied with `BrowserContext.route()` (plus `routeWebSocket()`), which every
request passes through regardless of what triggered it. The argument check on `browser_navigate` is
kept as an outermost, least-trusted layer only, for a fast readable error and to stop `file://`
before it loads.

**Matching rules** (same vocabulary and semantics as `@playwright/mcp`'s `--allowed-origins` /
`--blocked-origins`):

| Entry | Matches |
|---|---|
| `example.com` | `http://example.com`, `https://example.com` -- **default port only** |
| `example.com:8443` | that host on that port |
| `example.com:*` | that host on any port |
| `*.example.com` | any subdomain; **not** the apex -- list `example.com` separately |
| `https://example.com` | that scheme only |
| `[::1]:8080` | IPv6 literal |

A target on a non-standard port must name the port, or use `:*`. Entries that do not parse are
rejected at start-up rather than silently never matching.

**Defaults.** Permissive: with no `allowedOrigins` configured every origin is reachable, and with no
`allowedUploadDirectories` configured `browser_upload_file` is unrestricted. Both are announced on
stderr at start-up and in the MCP `instructions`. Once an allowlist *is* configured it fails closed:
anything that does not match is blocked, including schemes that carry no matchable origin.

**Always on, regardless of configuration.** `file:`, `filesystem:`, `chrome:`, `chrome-untrusted:`,
`chrome-extension:`, `devtools:` and `view-source:` are always refused, and only `about:blank` /
`about:srcdoc` are permitted among `about:` URLs. `blockedSchemes` adds to this list; it cannot
remove from it. `file://` matters most: it reads local disk and never crosses an HTTP proxy, so
proxy-history auditing cannot see it.

**Uploads.** `browser_upload_file` resolves `..` and then symlinks (`realpath`) before checking
containment, so a path that escapes the allowlist is rejected however it is spelled.

**Visibility.** Every block is logged to stderr and appended to the result of the tool call that
caused it, naming the blocked origin -- a silently dropped request is indistinguishable from a
broken target.

**Known gaps.** See `HARDENING-2.md` for what is and is not caught, with measurements.

### Stealth Chromium via CloakBrowser

The `playwright` provider can optionally launch [CloakBrowser](https://cloakbrowser.dev/) instead of vanilla Chromium for sessions that need to bypass bot detection. Enable it per-config or via env:

```json
{
  "providers": {
    "playwright": { "useCloakBrowser": true }
  }
}
```

```bash
PLAYWRIGHT_USE_CLOAKBROWSER=true
```

`cloakbrowser` is an optional peer — install it only when you need stealth:

```bash
npm install cloakbrowser
```

The CloakBrowser binary (~200MB stealth Chromium) is downloaded automatically on the first session launch. Existing `launchOptions` / `contextOptions` continue to apply, and the rest of the provider behaves identically to standard Playwright.

Required credentials by provider:
- `playwright`: none
- `browserbase`: `BROWSERBASE_API_KEY`, plus a `projectId` in config or `BROWSERBASE_PROJECT_ID`
- `anchor`: `ANCHOR_API_KEY`
- `cloudflare`: `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_ACCOUNT_ID`

Optional env defaults:
- `BROWSERBASE_PROJECT_ID`
- `BROWSERBASE_KEEP_ALIVE`
- `BROWSERBASE_CONTEXT_ID`
- `BROWSERBASE_PERSIST`
- `PLAYWRIGHT_STORAGE_STATE_PATH`
- `PLAYWRIGHT_EXECUTABLE_PATH`
- `PLAYWRIGHT_CHANNEL`
- `PLAYWRIGHT_USE_CLOAKBROWSER` (`true` to launch stealth Chromium via [CloakBrowser](https://cloakbrowser.dev/); requires `npm install cloakbrowser`)

## Installation

Use the standard config below in any MCP client that supports stdio:

```json
{
  "mcpServers": {
    "parallel-browser-mcp": {
      "command": "npx",
      "args": ["parallel-browser-mcp@latest"],
      "env": {
        "BROWSER_MCP_CONFIG": "{\"defaultProvider\":\"playwright\",\"providers\":{\"playwright\":{\"launchOptions\":{\"headless\":true}}}}",
        "BROWSERBASE_API_KEY": "your_browserbase_key",
        "ANCHOR_API_KEY": "your_anchor_key"
      }
    }
  }
}
```

<details>
<summary>Claude Code</summary>

Use the Claude Code CLI to add the server:

```bash
claude mcp add parallel-browser-mcp npx parallel-browser-mcp@latest
```

If you need provider configuration, add the environment variables in your Claude MCP config using the standard config above.
</details>

<details>
<summary>Claude Desktop</summary>

Follow the Claude Desktop MCP install flow and use the standard config above in the local MCP configuration file.
</details>

<details>
<summary>Codex</summary>

Use the Codex CLI:

```bash
codex mcp add parallel-browser-mcp npx "parallel-browser-mcp@latest"
```

Or add this to `~/.codex/config.toml`:

```toml
[mcp_servers.parallel-browser-mcp]
command = "npx"
args = ["parallel-browser-mcp@latest"]
```
</details>

<details>
<summary>Copilot</summary>

Use the Copilot CLI interactive flow:

```text
/mcp add
```

Or add this to `~/.copilot/mcp-config.json`:

```json
{
  "mcpServers": {
    "parallel-browser-mcp": {
      "type": "local",
      "command": "npx",
      "tools": ["*"],
      "args": ["parallel-browser-mcp@latest"],
      "env": {
        "BROWSER_MCP_CONFIG": "{\"defaultProvider\":\"playwright\",\"providers\":{\"playwright\":{\"launchOptions\":{\"headless\":true}}}}",
        "BROWSERBASE_API_KEY": "your_browserbase_key",
        "ANCHOR_API_KEY": "your_anchor_key"
      }
    }
  }
}
```
</details>

<details>
<summary>Cursor</summary>

Go to `Cursor Settings` -> `MCP` -> `Add new MCP Server`, then use:

- command: `npx`
- args: `parallel-browser-mcp@latest`

Or paste the standard config above into the MCP config editor.
</details>

<details>
<summary>Gemini</summary>

Add the server to `.gemini/settings.json`:

```json
{
  "mcpServers": {
    "parallel-browser-mcp": {
      "command": "npx",
      "args": ["parallel-browser-mcp@latest"],
      "env": {
        "BROWSER_MCP_CONFIG": "{\"defaultProvider\":\"playwright\",\"providers\":{\"playwright\":{\"launchOptions\":{\"headless\":true}}}}",
        "BROWSERBASE_API_KEY": "your_browserbase_key",
        "ANCHOR_API_KEY": "your_anchor_key"
      }
    }
  }
}
```
</details>

<details>
<summary>VS Code</summary>

Use the MCP install flow in VS Code with the standard config above, or install with the VS Code CLI:

```bash
code --add-mcp '{"name":"parallel-browser-mcp","command":"npx","args":["parallel-browser-mcp@latest"]}'
```
</details>

## Example Flow

1. Call `start_session` with `{ "provider": "playwright" }`
2. Read the returned session `id`
3. Call `browser_navigate` with `{ "sessionId": 1, "url": "https://example.com" }`
4. Call any additional `browser_*` tool with the same `sessionId`
5. Call `close_session` when done

## Development

```bash
corepack pnpm install
corepack pnpm typecheck
corepack pnpm test
corepack pnpm test:coverage
corepack pnpm build
corepack pnpm smoke:local
```

## Publishing

This repo is set up to publish as an npm package:

- the CLI entrypoint is `parallel-browser-mcp`
- production builds exclude tests and smoke scripts
- the published package only includes `dist`, `README.md`, and `.env.example`

Before publishing:

```bash
corepack pnpm typecheck
corepack pnpm test
corepack pnpm build
npm pack --dry-run
```

GitHub Actions publishing:

- `.github/workflows/publish.yml` publishes to npm on GitHub release publication or manual dispatch
- set the `NPM_TOKEN` repository secret before using the publish workflow

## Examples

- `examples/local` contains a standalone npm package that connects to `parallel-browser-mcp` with `@langchain/mcp-adapters` and runs a LangChain agent against the local Playwright provider.
- `examples/browserbase` contains a standalone npm package that connects LangChain to the published MCP server with Browserbase config and prompts the agent to use `browser_screenshot`.
- `examples/anchor` contains a standalone npm package that connects LangChain to the published MCP server with Anchor config and prompts the agent to use `browser_snapshot`.
- `examples/cloudflare` contains a standalone npm package that connects LangChain to the published MCP server with Cloudflare Browser Run config and prompts the agent to use `browser_snapshot`.
- The root `.npmignore` excludes the full `examples` directory from npm publishing.

## Testing

The repo includes:
- unit coverage for config loading, providers, registry behavior, session tools, and representative browser tools
- a local Playwright smoke script in `src/smoke/localSmoke.ts`
- an end-to-end security-policy proof in `src/smoke/securityPolicySmoke.ts` (`npm run smoke:security`),
  which drives a real server over stdio against two local origins and asserts, server-side, that the
  out-of-scope one receives nothing

## Notes

- `start_session` is intentionally small. Provider-specific behavior belongs in MCP configuration, not tool inputs.
- The server logs to stderr so stdout stays clean for MCP JSON-RPC traffic.
- Browserbase and Anchor Browser are normalized to Playwright page operations after connection, so the browser tools stay provider-agnostic.
