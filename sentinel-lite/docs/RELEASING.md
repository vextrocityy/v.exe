# Releasing Vigil

## 1. One-time: update-signing key

```powershell
sentinel-service keygen
# secret (keep OFFLINE, never commit): 9f…
# public (build with SENTINEL_UPDATE_PUBKEYS=…): 3c…
```

* Store the **secret** in an offline vault or HSM. Anyone holding it can push signatures to
  every installation (signatures can quarantine files).
* Put the **public** key in the GitHub repository variable `SENTINEL_UPDATE_PUBKEYS`
  (Settings → Secrets and variables → Actions → Variables). The `installer` CI job compiles it in.
  Several comma-separated keys are allowed, so you can rotate keys: ship a build trusting old + new,
  then start signing with the new one.

Builds without a key still work; they just ignore the official channel (community feed only).

## 1b. Community feed key (abuse.ch)

The MalwareBazaar export needs an abuse.ch Auth-Key. Each installation can enter its own key in
Settings, or you can pre-seed `abusech_auth_key` in `%ProgramData%\SentinelLite\settings.json`
through your deployment tooling. **Before shipping a product that uses the feed commercially,
confirm abuse.ch's terms**: their API documentation says commercial use may require an enhanced
agreement. Add the key as the `ABUSECH_AUTH_KEY` repository secret to enable the live feed check in CI.

## 1c. YARA rules and licensing

Installations download the **YARA Forge "core"** package
(`github.com/YARAHQ/yara-forge` releases) at runtime; the installer itself only ships the harmless
self-test rule in `rules/sentinel-test.yar`. Forge aggregates rules from many authors under their
own licenses (each rule's `license` meta): mostly **CC BY-SA 4.0** and the **Detection Rule License 1.1**,
plus Volexity's own license, Apache-2.0, BSD-2-Clause, MIT and others; some rules carry no license field.
**Before selling the product, have the licenses reviewed** (attribution requirements, and whether any
source restricts commercial use). If needed, point the feed at a Forge package you filter yourself, or
ship your own signed rule set.

To add private rules, drop `.yar` files into `%ProgramData%\SentinelLite\rules\` (administrators
only) and restart the service, or wait for the next update. Use `sentinel-service yara-check <dir> [path]`
to compile-check rules and test them against sample files before deploying.

## 2. Publishing a signature pack

```powershell
# pack.json: { "name": "official", "version": "2026.11.07.1", "signatures": [ { "sha256": "…", "name": "Trojan.X", "severity": "high" } ] }
sentinel-service sign-pack pack.json secret.key      # writes pack.json.sig
```

Upload `pack.json` and `pack.json.sig` side by side over HTTPS and set `update_url` in the
installation's settings (or ship it as a default in `settings.json`). Rules:

* `version` is dotted-numeric and **must increase**; clients refuse older packs (rollback protection).
* Each pack replaces nothing: hashes accumulate. To retract a false positive, publish the hash
  in the allow-list (Phase 2), or re-release it with `"severity": "info"`.
* Test against a staging machine first: a bad hash in an official pack *will* be quarantined.

## 3. Building the installer

```powershell
$env:SENTINEL_UPDATE_PUBKEYS = "<public key hex>"
.\scripts\build-release.ps1
# -> target\release\bundle\nsis\Vigil_<version>_x64-setup.exe
```

CI (`.github/workflows/sentinel-lite.yml`) does the same on every push, then installs it silently,
checks the service, the bundled signatures, the autostart entry and that a client copied outside
the install directory is refused, and uninstalls it.

## 4. Code signing (required before distributing)

Unsigned installers trigger SmartScreen warnings and are often blocked by other security
products. Use an **EV or OV code-signing certificate** (or Azure Trusted Signing) and add to
`ui/src-tauri/tauri.bundle.conf.json`:

```json
"bundle": { "windows": { "signCommand": "trusted-signing-cli -e https://eus.codesigning.azure.net -a <account> -c <profile> %1" } }
```

Tauri runs it for the dashboard, the bundled `sentinel-service.exe` and the installer. Signing
the engine also matters for the IPC trust model and for future ELAM / PPL work.

## 5. Release checklist

- [ ] Version bumped in `Cargo.toml` (workspace) and `ui/src-tauri/tauri.conf.json` / `ui/package.json`
- [ ] If the IPC protocol changed: `PROTOCOL_VERSION` bumped (old dashboards will refuse to connect)
- [ ] New DB schema changes added as a **new** entry in `MIGRATIONS` (never edit shipped ones)
- [ ] CI green: engine tests + Windows smoke test + installer job
- [ ] Installer and binaries code-signed
- [ ] Upgrade tested over the previous release (settings, quarantine and history preserved)
