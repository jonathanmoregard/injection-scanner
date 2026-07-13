# Secret loading (agenix-capable, fail-loud)

`injection_scanner.keyloader.load_key` resolves every API key through three
tiers, in strict precedence order:

1. **FILE** — `<NAME>_FILE` points at a decrypted secret file (the agenix
   pattern).
2. **env** — `<NAME>` holds the secret value directly.
3. **keyring** — `secret-tool lookup app research-agent key <keyring-key>`.

## The agenix FILE pattern

agenix does not put a secret's *value* into a service's environment. It
decrypts the secret to a FILE and exposes its path:

```nix
config.age.secrets.lakera-api-key.path  # => /run/agenix/lakera-api-key
```

You wire that path (not the value) into the service environment under the
`*_FILE` variable:

```nix
systemd.services.research-agent.environment = {
  ANTHROPIC_API_KEY_FILE = config.age.secrets.anthropic-api-key.path;
  OPENAI_API_KEY_FILE    = config.age.secrets.openai-api-key.path;
  LAKERA_API_KEY_FILE    = config.age.secrets.lakera-api-key.path;
};
```

At runtime `load_key` reads the file and returns its stripped contents.

## Fail-loud contract

**All config issues lead to loud rejection, never silent degradation.**

If a `*_FILE` variable is **set**, the operator intended agenix (or a
comparable manager) to provide the secret via that file. If the file is
then missing, unreadable, or empty/whitespace-only, that is a **botched
mount** — the secret did not arrive. `load_key` raises `KeyConfigError`
naming the `*_FILE` variable and the path. It does **not** fall through to
the env var or keyring, because doing so would mask a real deployment
failure.

- A `*_FILE` set to the empty string is treated as "not configured" and
  falls through to the lower tiers (it carries no path).
- A **keyring miss** (secret not found) is not a misconfiguration and
  returns `None` — absence is allowed at the lowest tier.
- `load_key` returns `None` only when **no** source is configured at all.
  The caller decides whether that is fatal. For the honeypot and the
  Lakera layer it is: they reject.

In the honeypot, a `KeyConfigError` from a broken `*_FILE` mount is caught
into a `Honeypot_Skipped` result with signal `unavailable:key-config-error`,
which flows into the standard fail-closed path (`ok=False`) so the scan
rejects loudly with a clear reason instead of crashing.

## Env var → keyring-key mapping

| Secret         | FILE env var (agenix) | Value env var       | Keyring key         |
| -------------- | --------------------- | ------------------- | ------------------- |
| Anthropic API  | `ANTHROPIC_API_KEY_FILE` | `ANTHROPIC_API_KEY` | `anthropic-api-key` |
| OpenAI API     | `OPENAI_API_KEY_FILE`    | `OPENAI_API_KEY`    | `openai-api-key`    |
| Lakera API\*   | `LAKERA_API_KEY_FILE`    | `LAKERA_API_KEY`    | `lakera-api-key`    |

All keyring lookups use the fixed attributes `app research-agent key
<keyring-key>`.

\* Reserved for the Lakera layer, which arrives on a separate branch. The
loader already supports the mapping; the Lakera integration wires it up.
