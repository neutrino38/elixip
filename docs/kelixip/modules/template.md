# <module_name>

> Module documentation template. Copy this page for a new module and fill each
> section. Keep the section order so every module reads the same way.

One-paragraph overview: what the module does and when you would load it.

## Loading

Where the block lives (`config.toml`, or `domains.toml` for domain-tied
modules), and the `import` a script uses.

```toml
# config.toml   (or domains.toml)
[module.<name>]
# … parameters …
```

```elixir
import Kelix.Mod.<Camelize(name)>, only: [<fun>: <arity>]
```

## Parameters

| Key | Type | Default | Description |
|---|---|---|---|
| `call_timeout_ms` | integer | `5000` | Upper bound on a facade call (ms) |
| … | … | … | … |

Required keys should say **required** in the Default column.

## Facades

The functions a script imports. Give each one's signature and its return
contract, including the failure values a non-blocking facade can return
(`{:error, :down}`, `{:error, :timeout}`).

### `fun/arity`

```elixir
fun(arg1, arg2) :: {:ok, term} | :notfound | {:error, term}
```

Describe the semantics and each return shape.

## Control commands

`kelictl <name> <cmd>` / `/modules/<name>/…` contributed by the module, or
**none yet**. (Frontals: P7.)

## Events

Messages the module sends to subscribers, if any — otherwise **none**.

## Examples

A realistic config block plus a script excerpt using the facade.
