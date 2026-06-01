# Dependency Budget

> "Minimize dependencies. … Every dependency increases attack surface. Justify each
> one." — project security guidelines

Citadel is a *from-scratch, privacy-first* engine. Today the workspace resolves to
**766 crates** — most of them pulled by the GUI, JS, and HTTP stacks. This document
defines what we **keep**, what we **replace**, what we **drop**, and the rule for
adding anything new. It is the contract that the per-subsystem rewrites (and CI
`deny.toml`) are measured against.

## The rule (operationalized)

The default answer to "add a dependency" is **no**. A new dependency is admissible
only if **all** of:

1. It is **security-critical to get right** (crypto, TLS, Unicode) **or** would cost
   prohibitively many engineer-years to write well (a fuzzed HTML parser).
2. It is **actively maintained** and ideally **independently audited**.
3. Its license is in the `deny.toml` allow-list.
4. The PR adding it **documents the justification** and which tier it lands in.

One hard exception in the other direction: **never hand-roll cryptography or TLS.**
Rolling our own AEAD/TLS would be the single worst regression a security browser
could make. Crypto/TLS is always a vetted dependency.

## Tiers

### Tier 0 — KEEP (vetted, security-critical, do-not-reinvent)
The permanent allow-list. These never get a from-scratch replacement.

| Crate(s) | Why |
|----------|-----|
| `rustls`, `rustls-native-certs`, `webpki`/`rustls-webpki` | TLS. Never hand-roll. (Consolidate onto **one** rustls version — see roadmap.) |
| `aes-gcm`, `aead`, `chacha20`, `ghash`, `polyval`, `cipher` | AEAD for the ZKVM channel. |
| `blake3`, `sha2`, `digest` | Hashing / MAC. |
| `zeroize` | Wipe key material. |
| `getrandom` (+ `rand_core`) | OS CSPRNG entropy. |

### Tier 1 — KEEP FOR NOW (high-quality, well-fuzzed, expensive to replace)
Kept deliberately; revisit only after Tier 2/3 land. Replacing these is where
browsers go to die, and they're already fuzzed/audited.

| Crate(s) | Role | Note |
|----------|------|------|
| `html5ever`, `markup5ever`, `tendril` | HTML parsing | Servo, fuzzed. Huge to replace. |
| `cssparser`, `selectors` | CSS parsing/selectors | Servo (MPL-2.0). Huge to replace. |
| `unicode-*`, `icu_*` | Unicode tables / normalization | Correctness-critical; do not hand-maintain. |
| `taffy` | Flexbox/grid layout | Small, good. Candidate to internalize during Stage B. |
| `serde`, `serde_json` | ZK channel (de)serialization | Ubiquitous/vetted; revisit (could hand-roll the few message types). |

### Tier 2 — REPLACE (control + attack surface; tractable)
Targets for from-scratch replacement, in priority order.

| Subsystem | Drags in | Replace with | Effort | Leverage |
|-----------|----------|--------------|--------|----------|
| **GUI**: `iced` + `wgpu` + `winit` + `cosmic-text`/`swash`/`glyphon` | **~half the tree** (the worst license/advisory offenders) | software rasterizer painting the **ZK display list** to a framebuffer + minimal windowing (`softbuffer`/platform) | High | **Highest** |
| **HTTP**: `reqwest` + `hyper` + `native-tls`/`openssl` | dozens (forced the openssl/native-tls bans off) | minimal HTTP/1.1 (then h2) over **rustls** | Medium | High |
| **DNS**: `hickory-resolver` | dozens (the rustls-webpki CVEs) | minimal DoH/DoT client over rustls | Medium | High |
| **Images**: `image` (png/jpeg/gif) | moderate | per-format decoders, incrementally (PNG first) | Low–Med | Incremental |

The GUI cut is highest-leverage because the ZK boundary **already emits a display
list** — the seam to render it ourselves exists today. Font *shaping* is the one
hard part; a single bundled font + basic shaping is a defensible v1.

### Tier 3 — DROP (remove entirely)
| Crate(s) | Rationale |
|----------|-----------|
| `env_logger` | Already banned in `deny.toml`; use a minimal logger. |
| `chrono` | Prefer `std::time` where feasible. |

> **`boa_engine` — dropped, then deliberately re-introduced.** Boa was first
> removed (commit `37993b6`) when JS was off. It is now **back, on purpose**, as
> the vetted **engine core** of **CitadelJSEngine**: pure Rust (no native attack
> surface), run inside the per-tab ZK boundary, behind a from-scratch
> privacy binding cage, and only as **explicit opt-in**. The earlier `thin-vec`
> advisory is gone (Boa re-resolved to a patched version; `cargo deny`/`audit`
> clean). This is the intended end-state, not a budget regression — we keep a
> *vetted* engine rather than hand-roll a JS interpreter. The binding cage, not
> ECMAScript, is where the effort goes.

## Targets

- **Total crates:** 766 → 659 (networking cut) → 602 (Boa removed) → back up with
  Boa re-introduced as the vetted JS core; **≤ ~200** target after the Tier 2 GUI
  cut, **≤ ~120** after further trimming. (Servo parsers + Unicode + crypto + the
  vetted JS engine keep a floor.)
- **Direct workspace dependencies:** curated; every entry maps to a tier above.
- Track the number in CI (a simple `cargo tree`/`deny list` count step) and treat
  regressions as review-blocking.

## Enforcement

- `deny.toml` `[bans].deny`: **restore** `openssl`, `native-tls`, `reqwest`,
  `env_logger`, `ureq`, `curl` to the ban list **as each Tier 2/3 removal lands**
  (they were emptied only because the engine currently pulls them).
- `deny.toml` `[advisories].ignore`: shrinks as Tier 2 removes the deps behind the
  rustls-webpki / thin-vec / rand advisories — those ignores should disappear, not
  accumulate.
- Re-ratchet CI clippy/coverage gates (see ci.yml TODOs) on the smaller tree.
- New-dependency PRs: justification + tier, per "The rule" above.

## Sequencing (fits the staged roadmap)

1. **Now:** this budget + restore-able ban list documented (done).
2. **Stage B (faithful rendering):** build real layout/paint for the display list —
   this is also the foundation for the Tier 2 GUI cut.
3. **GUI cut:** software rasterizer + windowing → drop iced/wgpu; re-add openssl/
   native-tls bans become possible once HTTP is also migrated.
4. **Networking cut:** minimal HTTP+DoH over rustls → drop reqwest/hickory; restore
   the network-stack bans; remove the rustls-webpki ignores. **(done)**
5. **Boa:** removed while JS was off, then **re-introduced as the vetted JS core**
   of CitadelJSEngine (opt-in, inside the ZK cage). **(done)**
6. **Re-ratchet** advisories/bans/clippy/coverage to the smaller, audited tree.
