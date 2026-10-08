# Offline embedding cache

ShieldCortex ranks memories for search and dedup with a small local embedding
model, `Xenova/all-MiniLM-L6-v2`, run by transformers.js. By default the model
is downloaded from huggingface.co the first time it is needed and cached under
`~/.cache/shieldcortex/models`.

This page covers three settings for hosts that cannot, or should not, download
it on demand: a custom cache location, an offline switch, and a mirror.

## Scope: embeddings only

`SHIELDCORTEX_EMBEDDINGS_OFFLINE` stops **the embedding model** from being
fetched. It is not a product-wide zero-egress switch. Other features have their
own network behaviour and are configured separately, for example:

- update and version checks (`shieldcortex update`, the dashboard),
- cloud sync and any remote integration you have configured,
- the optional review copilot and defence judge models, which have their own
  model directories and download settings.

## Settings

| Variable | Values | Default |
|---|---|---|
| `SHIELDCORTEX_MODEL_DIR` | Absolute path, `~` or `~/…` | `~/.cache/shieldcortex/models` |
| `SHIELDCORTEX_EMBEDDINGS_OFFLINE` | `1`/`true`/`yes`/`on`, or `0`/`false`/`no`/`off` | off |
| `HF_ENDPOINT` | `https://` URL, optionally with a path prefix | huggingface.co |

Set them in the environment of every process that uses memory: the MCP server,
the hooks, the API and the CLI. The embedding worker, the cache checks and
`shieldcortex doctor` all read the same three variables, so they always agree
on which directory and which mode they are looking at.

### `SHIELDCORTEX_MODEL_DIR`

The cache **root**. The model itself lives in
`<root>/Xenova/all-MiniLM-L6-v2/`, the same layout as the default location.

- Unset or empty: the default root.
- `~` and `~/…` expand to your home directory.
- Relative paths, `~user/…`, values with leading or trailing spaces and values
  containing a NUL byte are rejected. Hooks and servers start in different
  working directories, so a relative path could point to a different place for
  each of them.

An invalid value is never replaced by the default: embeddings stay off and
`shieldcortex doctor` names the problem.

### `SHIELDCORTEX_EMBEDDINGS_OFFLINE`

When on:

- the model is loaded only from the cache; nothing is downloaded, including
  the tokenizer and config files;
- if the cached `model.onnx` fails to load as corrupt, it is **left in place**.
  Online, ShieldCortex moves a corrupt weight aside and downloads it once more;
  offline, that download cannot happen, so the file is not moved and the error
  says to replace it;
- `shieldcortex doctor` reports a missing or incomplete cache as a warning
  rather than "will download on first recall".

Any value other than the ones in the table is rejected and embeddings stay off.

### `HF_ENDPOINT`

transformers.js does not read `HF_ENDPOINT` by itself. ShieldCortex validates
it and passes it on as the library's download host. The path is kept:
`HF_ENDPOINT=https://mirror.example.com/hf` downloads
`https://mirror.example.com/hf/Xenova/all-MiniLM-L6-v2/resolve/main/config.json`
and so on, so the mirror must serve the Hugging Face `resolve/main` layout.

Rejected, with embeddings left off:

- anything other than `https://` (plain `http://` is accepted only for
  `localhost`, `127.0.0.1` and `[::1]`),
- a username or password in the URL,
- a query string (`?…`) or fragment (`#…`).

Because the variable is shared with other Hugging Face tools, a host that
already exports `HF_ENDPOINT` for them now uses it for this model too; if that
value fails the checks above, embeddings stay off until it is fixed or unset.

Error messages never print the value. transformers.js sends `HF_TOKEN` only to
huggingface.co, so a mirror does not receive it. With the offline switch on,
`HF_ENDPOINT` is still validated but nothing is downloaded from it.

## Provisioning an offline host

1. On a machine that can reach huggingface.co (or your mirror), get these four
   files for `Xenova/all-MiniLM-L6-v2`. Either copy them from a working
   ShieldCortex install's `~/.cache/shieldcortex/models/Xenova/all-MiniLM-L6-v2/`,
   or download them from
   `https://huggingface.co/Xenova/all-MiniLM-L6-v2/resolve/main/<file>`:

   ```
   config.json
   tokenizer.json
   tokenizer_config.json
   onnx/model.onnx
   ```

2. Check the weight. ShieldCortex expects exactly this file and treats anything
   else as corrupt:

   ```bash
   stat -c %s onnx/model.onnx   # 90387606
   sha256sum onnx/model.onnx    # 759c3cd2b7fe7e93933ad23c4c9181b7396442a2ed746ec7c1d46192c469c46e
   ```

3. Copy the directory to the offline host, keeping the layout:

   ```
   <root>/Xenova/all-MiniLM-L6-v2/config.json
   <root>/Xenova/all-MiniLM-L6-v2/tokenizer.json
   <root>/Xenova/all-MiniLM-L6-v2/tokenizer_config.json
   <root>/Xenova/all-MiniLM-L6-v2/onnx/model.onnx
   ```

4. Set `SHIELDCORTEX_MODEL_DIR=<root>` (skip this if you used the default root)
   and `SHIELDCORTEX_EMBEDDINGS_OFFLINE=1`, then run `shieldcortex doctor`.

## Reading the doctor row

The `Embeddings` row checks files on disk. It does not load the model or run
inference, and a passing row says so ("files only, inference not exercised").
It reports:

- **pass**: `model.onnx` has the expected size and hash, and the tokenizer and
  config files are present;
- **warn, offline**: the model or one of its files is missing, or the weight is
  corrupt. Nothing will be downloaded; provision the files as above;
- **info, online**: something is missing and will be downloaded on first use;
- **warn, configuration invalid**: one of the three variables was rejected.

The row also shows the offline mode, a `SHIELDCORTEX_MODEL_DIR` root, and the
mirror host when one is in use. Doctor never downloads the model.
