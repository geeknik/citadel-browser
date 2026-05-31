# Zero-Knowledge Tab — Threat Model & Proofs

This document states, without marketing, what Citadel's "zero-knowledge tab"
boundary guarantees today, how each guarantee is **proven by an executable test**,
and — just as importantly — what it does **not** yet guarantee.

## Terminology (read this first)

"ZKVM" here means an **isolated virtual machine / renderer that the host has zero
knowledge of the internals of**, communicating only through a narrow, encrypted
message channel. It is **not** a zero-knowledge *proof* system (no zk-SNARK/STARK,
no cryptographic attestation). Do not read "zero-knowledge" as "cryptographically
proven blindness." Read it as: *the host's render path is built so it can only ever
hold a sanitized display list, never the tab's internal state.*

## What crosses the boundary

```
            host (browser process)                 isolation boundary (renderer task)
  URL ─────────────────────────────────────────────►  parse untrusted HTML
  raw HTML bytes ──[encrypted Channel: render_page]─►  sanitize at DOM level
                                                        (drop script/style/iframe,
                                                         strip js:/data: hrefs)
                                                        block-flow layout
  RenderedContent ◄─[encrypted Channel: rendered]───  positioned display list only
  (display list)
```

The **only** type that returns across the boundary is `RenderedContent`: a flat
list of positioned, styled text/link runs plus layout size and a count of blocked
elements. No DOM, no scripts, no comments, no attributes, no raw markup.

## Proven properties

Run them: `cargo test -p citadel-tabs --test zkvm_isolation_proof`
(and the end-to-end render: `--test zkvm_render_example_com`).

| # | Property | Test |
|---|----------|------|
| 1 | **Boundary minimality** — scripts, script bodies, comments, event handlers, `data-*` attributes, raw tags, and `javascript:`/`data:` schemes never appear in the serialized payload the host receives; only visible text/safe links do. | `only_sanitized_display_list_crosses_the_boundary` |
| 2 | **Pure renderer, no cross-tab state** — 64 interleaved concurrent renders of two tabs each always equal their own isolated result; no shared/global state to leak between tabs. | `renderer_is_pure_with_no_cross_tab_contamination` |
| 3 | **Confidential, tamper-evident, per-tab channel** — AES-256-GCM: plaintext never appears in ciphertext, a single flipped byte fails closed, and a different tab's key cannot decrypt this tab's traffic. | `channel_payloads_are_encrypted_authenticated_and_per_tab` |
| 4 | **Isolated buses** — each tab rides an independent channel; one tab's VM never observes another tab's messages. | `cross_tab_channels_are_isolated_buses` |
| 5 | **Type-level non-leakage** — `RenderedContent` is structurally incapable of carrying a DOM/script/raw bytes; a dangerous-only page yields an empty display list. | `host_visible_type_carries_only_display_primitives` |

Net effect: **the browser's rendering/UI code cannot infer a tab's scripts,
markup, hidden attributes, comments, or another tab's content** — it only ever has
the sanitized display list for the tab it is showing.

## What the host DOES learn (honest scope)

The host is not blind to the tab. Today it learns, by construction:

- the **URL** (the host's network layer fetches it),
- the **raw HTML bytes** (the host fetches them and hands them *into* the boundary),
- the **title, byte size, element count**, and
- the **sanitized display list** (which is the visible page content).

So the current guarantee is precisely: *the dangerous, untrusted processing
(parsing, script handling, layout of attacker-controlled input) is isolated, and
the host renderer is fed only a sanitized result.* It is a **rendering/parsing
sandbox with a clean boundary**, not a host that knows nothing about the tab.

## Gaps to a TRUE zero-knowledge tab (not yet closed)

1. **Same OS process.** The renderer is a `tokio` task in the browser process, not
   a separate process/sandbox. Nothing at the OS/hardware level stops host code
   from reading the renderer's memory. The encrypted channel only yields real
   confidentiality once the boundary is a **separate process, seccomp jail, WASM
   sandbox, or enclave**. The channel is already serialized + AEAD-encrypted
   specifically so it can be lifted to such a boundary without redesign.

2. **Host performs the fetch.** Because the host fetches and holds the raw bytes,
   it inherently knows the URL and content. A content-blind tab requires moving the
   **fetch inside the boundary** (host hands in only a URL — or a user-entered URL
   routed straight to the VM — and gets back only a display list).

3. **No attestation.** There is no cryptographic proof to a third party that a given
   display list was produced by the unmodified isolated renderer. That needs remote
   attestation (e.g. enclave quoting) and is out of scope.

## Roadmap to close the gaps

1. Relocate `spawn_zkvm_renderer` into a child process; replace the in-process
   `Channel` mpsc with a length-prefixed pipe/socket carrying the **same encrypted
   `EncryptedMessage` frames**. Proofs 1, 3, 4, 5 carry over unchanged.
2. Move fetch (`citadel-networking`) inside the boundary; host passes only a URL.
   The host then learns URL + display list, never raw bytes/DOM.
3. Add seccomp/WASM confinement to the child so a renderer RCE cannot reach the
   network or filesystem; add optional enclave + attestation for property 3.

Until step 1 lands, claims should say "isolated rendering boundary with a sanitized,
encrypted interface," not "the host cannot access the tab's memory."
