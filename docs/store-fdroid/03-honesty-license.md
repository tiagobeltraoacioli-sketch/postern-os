# The AGPL constraint, the trust model, and the honest limits

Status: design only. No code, no deploy, no schema migration performed here.
This is the third of a three-part split:

- `01-architecture.md` — the repo index format, self-hostable repos, the
  multi-repo client, host-class mapping, postmarketOS install path.
- `02-reproducible-builds.md` — the build verifier: pipeline, Nix advantage,
  verdict → badge mapping, attestation record schema.
- **This doc (03):** the AGPL/`fdroidserver` licensing constraint and the
  chosen resolution; the signed-index trust model synthesized across both
  other docs; the honest limits of what any of this actually proves; and a
  closing buildable-now-vs-hard assessment for the whole design.

This doc resolves the open questions both other architects deferred to it:
01's "generator tooling," "consuming real F-Droid repos," and "can AGPL
tooling run as a subprocess at all"; 02's "exact user-facing wording for
build≠safety," "should the verifier be its own licensed artifact," and
"CI-witnessed vs third-party-reproducible wording."

---

## 1. The AGPL constraint

### 1a. The problem, stated precisely

F-Droid's own repo-generation and build tooling, `fdroidserver`, is
**AGPL-3.0**. `deny.toml` (this repo's supply-chain policy) is explicit and
bright-line: permissive licenses only (MIT/Apache-2.0/BSD/ISC/Zlib/MPL-2.0-
for-unmodified-aggregation/etc.), with a one-line comment stating the
exclusion plainly — "Deliberately excludes AGPL/GPL/LGPL copyleft." The
Postern Apps roadmap (`docs/POSTERN-APPS-ROADMAP.md`) already anticipated
exactly this collision when it named **Depot** as the future attested-channel
product and, in the same table row, wrote: *"`tough` (AWS, MIT/Apache);
F-Droid GPL/AGPL — no code."* That is not a new decision this document is
making — it is a decision the team already made, being made concrete here.

Two things must not be conflated, because the honest answer differs for each:

1. **Can Postern's own code (the Depot index generator, the verifier
   orchestrator, the client) be, contain, or link AGPL code?** No — this is
   what `deny.toml` already forecloses for the crates workspace, and the
   roadmap's "no code" note extends that same rule to Depot's tooling even
   though Depot's build/index tooling doesn't live in the Cargo workspace
   `deny.toml` literally scans. The *policy*, not just the *tool*, is the
   thing being honored.
2. **Can Postern's build pipeline *invoke* an unmodified `fdroidserver`
   binary as an external subprocess — never forked, never patched, never
   distributed by Postern — the way a build might shell out to `gcc` or
   `ffmpeg`?** This is a real, separate question, addressed below.

### 1b. Why "external tool only" (option a) is legally arguable but rejected anyway

Running an AGPL program **unmodified**, as an arm's-length subprocess that
reads inputs and writes outputs — never linked, never distributed by
Postern, never itself modified — is a common pattern that does not, by
itself, place the *invoking* program under AGPL. AGPL's network-use clause
(§13) is triggered by *modifying* the AGPL-covered program and then making
the modified program available to users over a network; it is not triggered
merely by running an unmodified AGPL tool as part of a private build
pipeline. Read strictly, option (a) — external, unmodified, never-shipped
`fdroidserver` as build-time-only tooling — is defensible.

This design **does not take that path**. The reasons are practical and
policy-shaped, not because option (a) is clearly illegal:

- **`fdroidserver`'s actual functional surface doesn't fit what Depot needs,
  which makes "unmodified" hard to sustain.** `fdroidserver` is built for
  Android/Gradle-shaped submissions: `androguard` static analysis, APK
  metadata extraction, AndroidManifest parsing, a buildserver VM
  orchestration model tuned for reproducing Gradle/Android-SDK toolchains.
  Depot's actual build substrate is Nix (`02-reproducible-builds.md` §1a) —
  a `nix build` invocation, a store-path hash comparison, a diff against a
  shipped artifact. None of `fdroidserver`'s Android-specific machinery is
  useful here. The realistic outcome of trying to use it "unmodified" is
  that it gets patched to fit within months, at which point the *modified*
  program is what Postern is running — and if that patched fork is ever
  committed anywhere Postern controls (even a private CI-only repo), it is
  now a Postern-authored derivative of an AGPL work, with all the obligations
  that entails the moment it's conveyed to anyone, including a CI runner
  outside a single machine.
- **Bright-line auditability beats case-by-case legal reasoning.** `deny.toml`'s
  entire value as a policy is that it's a blanket rule cargo-deny can enforce
  mechanically — "permissive only, no exceptions" — rather than a set of
  narrow, continuously-revisited judgment calls about whether *this specific*
  invocation of *this specific* AGPL tool, in *this specific* deployment
  shape, stays on the safe side of §13. Extending Depot's tooling policy to
  "we do not run AGPL code in the build/release pipeline, full stop" keeps
  the same bright line the crates workspace already has, instead of adding a
  second, softer rule that needs a lawyer's judgment every time the CI
  topology changes (self-hosted runner vs. a shared/networked build service
  changes the §13 analysis).
- **The reimplementation is genuinely small.** F-Droid's *file-format ideas*
  — a signed index, packages separated from per-version build metadata, a
  detached signature — are not copyrightable; only `fdroidserver`'s
  *implementation* is AGPL. Postern already has the load-bearing primitive
  built and shipped: the Ed25519-detached-signature-over-exact-bytes scheme
  in `apps/postern-store/SIGNING.md`, which predates this design and owes
  nothing to `fdroidserver`'s code. What's left to write — walk a list of
  submissions, run the Nix verifier (`02`'s pipeline), assemble
  `postern.catalog/v1` JSON (`01`'s schema), sign it — is a modest amount of
  original glue code, not a reimplementation of `fdroidserver`'s Android
  build-farm orchestration, which Depot doesn't need in the first place.

**Resolution: option (b), a clean permissive reimplementation of the format,
verifier, and client — never fdroidserver's code, in any form, subprocess or
otherwise.** State this as firmly as the roadmap already does: no code from
F-Droid. Concepts (signed index, self-hostable repo, add-by-URL-and-key,
per-version metadata) are reused freely, because concepts aren't what the
license restricts.

### 1c. Consuming F-Droid's own repos (read-only) is a different, lower-stakes question

`01-architecture.md` flags whether the Store should become a genuine
*consumer* of upstream F-Droid's own `index-v2.json`/JAR-signed format, for
the existing `sloboda-compat`/`link` entries that already point at F-Droid
(`vocab.source.fdroid`). Reading a competitor's/upstream's published data
format is not a licensing problem — a file format is not copyrightable, and
parsing JSON someone else published is not "use of `fdroidserver`." The
constraint is narrower than 01's framing suggested: **the constraint is on
using `fdroidserver`'s *parsing code*, not on parsing F-Droid's *output
format*.** If the Store ever wants to render richer metadata for
`sloboda-compat` entries by reading F-Droid's real index, that requires
**writing an original, permissively-licensed reader for the subset of
`index-v2.json` fields needed** (a small JSON schema — package id, versions,
signer fingerprint) — never vendoring or porting any of `fdroidserver`'s own
Python. This is optional, low-priority scope, not a blocker to anything
else in this design — F-Droid remains, for `link`-tier entries, simply a URL
the Store points at (today's behavior), and richer parsing is a
nice-to-have deferred indefinitely.

### 1d. What this resolution costs

Being honest about the tradeoff: a from-scratch verifier/generator means
Depot does not inherit `fdroidserver`'s years of hardening against
Android/Gradle's specific nondeterminism sources. This cost is smaller than
it sounds, for the reason `02-reproducible-builds.md` §3–4 already
establishes: Depot's targets are Nix-packaged (first-party crates + nixpkgs
derivations for third-party apps), so the nondeterminism sources
`fdroidserver` had to fight (JDK/Gradle/Android-SDK environment drift) mostly
don't apply here — Depot is fighting a different, generally smaller set of
problems (§4 of `02`). Where Depot *does* eventually need to reach
Android/Gradle-built apps directly (rather than linking to F-Droid for them),
it inherits none of `fdroidserver`'s Android-specific reproducibility work
and would have to either build that capability from scratch or continue
deferring those apps to `link`-tier via F-Droid itself, as today's catalog
already does for every Android app in it (NewPipe, Aegis, Briar, Organic
Maps, Signal, WhatsApp — all `sloboda-compat`/`link`, none hosted).

---

## 2. The signed-index trust model (synthesized)

This section pulls together the trust model both other docs build pieces of,
states it as one coherent picture, and is explicit about where it is
genuinely weaker than a naive reading would assume.

### 2a. Two independent signature layers, never conflated

Per `01-architecture.md` §5, a `pmos-overlay`-tier install goes through
**two separate signatures that prove two separate things**:

| Layer | Scheme | Proves | Owned by |
|---|---|---|---|
| Depot index | Ed25519, detached, over exact index bytes | *This list of packages, and their claimed locations/metadata, came from whoever holds the pinned repo key* | The repo operator (Postern, or any third party running their own repo) |
| apk repository | RSA-4096, `abuild-sign`, over `APKINDEX.tar.gz` + each `.apk` | *This specific binary came from whoever holds that RSA key* | Alpine's own mechanism, unchanged, per `pmos-overlay/KEYS.md` |

Neither layer substitutes for the other. A VERIFIED Depot index says nothing
about whether the apk it points at is correctly signed; a validly-signed apk
says nothing about whether the Depot listing that led the user to it was
itself authentic. Both must hold for the full chain — "the list is real" +
"the binary is real" — to be true. This is the same "signature proves X,
not Y" discipline `apps/postern-store/SIGNING.md` already uses for the
catalog vs. per-app claims; it now applies across two crypto systems
instead of one.

### 2b. Trust establishment: no TOFU against the server

Per `01-architecture.md` §2, adding a repo means the user supplies **both
the URL and the pinned public key together, from a channel they already
trust** (the operator's own website, a QR code, a README) — never a bare
URL that the client then fetches a key from and trusts on first use. This
is the same principle the Store's own key-pinning already follows (the
curator key is a build-time constant baked into the CSP-hash-pinned page,
not fetched at runtime) and mirrors F-Droid's own add-repo-by-URL-and-
fingerprint pattern. It is worth stating plainly why this matters: **without
it, "self-hostable repos" would mean "anyone the user can be phished into
adding," not "anyone the user has independently verified.** The trust
doesn't come from cryptography alone — it comes from cryptography binding a
fingerprint the user obtained *out of band* to everything fetched afterward.

### 2c. Per-repo trust state, and an honestly weaker floor for third parties

`01-architecture.md` §2 generalizes the Store's existing
VERIFIED/TAMPERED/UNSIGNED/UNVERIFIED state machine to run per-repo. The
first-party Postern repo keeps today's floor — a CSP-hash-pinned embedded
fallback copy, so even a `file://`/offline open has *something* trustworthy
to show. **Third-party repos have no such floor.** Their fallback, on a
failed or first fetch, is only "the last snapshot this specific client
itself previously verified" — or nothing, on first use. This is a real,
disclosed asymmetry: adding a third-party repo is strictly a weaker trust
posture than the first-party one, and the UI must say so rather than
presenting every VERIFIED badge as equivalent regardless of which repo
earned it. A repo's trustworthiness is bounded by how well the user
verified the out-of-band fingerprint (§2b) — Depot cannot manufacture trust
a user didn't actually establish.

### 2d. Key rotation and revocation: an honest, currently-unsolved gap

Neither doc papers over this, and this document doesn't either. Bare
Ed25519-with-a-pinned-key, as specified for the near term, has **no
rotation story**: if a repo operator's key changes, every client that
pinned the old key sees the new index as TAMPERED (or an outright
verification failure) with no automatic recovery path — the user must
notice, re-verify out of band, and re-pin manually. `pmos-overlay/KEYS.md`
already documents the identical honest limitation for apk repo keys
("ship-new-key-first, then switch signing," a manual, disclosed procedure,
not an automated one) and states there is no CRL in `apk` — "revocation is
out-of-band + a fast key roll." Depot inherits the same shape of gap for
its own index-signing keys, and for the same reason: bare asymmetric
signing has no built-in notion of "this key is retired, trust the new one
instead" without a higher-level protocol.

This is precisely the gap **TUF** (Trust Update Framework) is designed to
close — role separation (a root role that can rotate the signing/targets
roles without every client needing a fresh out-of-band re-pin), explicit
rollback and freeze protection, and a defined key-compromise recovery
procedure. `apps/postern-store/SIGNING.md`'s own "Future upgrade: the Depot"
section already names TUF as the target state, alongside PQ hybrid signing
(Falcon-1024‖ML-DSA-65 — live today only for Consiglio login,
`crates/postern-consiglio-auth`) and per-artifact build hashes anchored to
the chain. **State this honestly rather than implying the near-term design
already has it solved:** the Ed25519-per-repo scheme specified in `01` is a
real, useful improvement over "no signature at all," and is forward-
compatible with a TUF upgrade (Ed25519 is a subset of what a TUF root role
can sign over), but rotation and revocation remain manual, disclosed,
user-visible failure modes until that TUF layer actually lands. Do not
badge or word the near-term scheme as though it has automatic key-rotation
safety it does not have.

### 2e. Self-hosted repos: no central gatekeeper cuts both ways

The whole point of the F-Droid model — and the reason it aligns with
Postern's ownerless ethos — is that no central authority approves which
repos exist. This is a genuine strength (nobody can deplatform an app by
refusing to list it) and a genuine cost that must be stated with equal
weight: **the client, not Postern, is the only thing standing between a
user and a malicious or careless third-party repo.** Postern cannot vet,
review, or vouch for a repo it didn't publish. A third-party repo can list
anything its operator wants, honestly-labeled or not, subject only to (a)
the same `normalizeEntry`-equivalent honesty-spine enforcement the client
applies uniformly (`01` §3 — proprietary can't claim `hosted_by_us`,
`attestable` requires a real verifier record, not a tier string) and (b)
whatever independent verification the user or the client is able to do.
Self-hostability is not curation; it is the explicit removal of curation as
a gatekeeper, replaced by cryptographic verifiability of *authenticity*
(this list came from this key) which is a different and weaker property
than *trustworthiness* (this key belongs to someone you should trust). The
Store's UI must never blur that line — a VERIFIED badge on a third-party
repo means "unmodified since you pinned this key," not "Postern
recommends this."

---

## 3. Honest limits — what none of this proves

### 3a. A reproducible build proves `binary == source`, not `source == safe`

This is the single most important thing to get right in the badge's
user-facing wording, and it is worth writing the actual copy rather than
leaving it as an abstract instruction, matching the register of the
existing EN/PT disclosure blocks in `pmos-overlay/DISTRIBUTION.md`:

> **EN — What the ATTESTED badge proves, and what it doesn't.**
> This app was built from its published source code in a reproducible
> environment, and the binary you're about to install is byte-identical to
> that build — verified independently, not just asserted by the publisher.
> What this **does not** prove: that the source code itself is safe,
> correct, or free of vulnerabilities. A reproducible build can faithfully
> reproduce a bug, or a deliberately malicious change, if that change was
> committed to the source we built. Judging the source's trustworthiness —
> code review, the maintainers' track record, how many independent people
> have read the diff — is a separate question this badge does not answer.
>
> **PT — O que o selo ATESTADO prova, e o que não prova.**
> Este aplicativo foi compilado a partir do código-fonte publicado, em um
> ambiente reprodutível, e o binário que você está prestes a instalar é
> idêntico, byte a byte, a essa compilação — verificado de forma
> independente, não apenas afirmado pelo publicador. O que isso **não**
> prova: que o código-fonte em si é seguro, correto ou livre de
> vulnerabilidades. Uma compilação reprodutível pode reproduzir fielmente um
> bug, ou uma alteração deliberadamente maliciosa, se essa alteração foi
> incluída no código-fonte compilado. Julgar a confiabilidade do
> código-fonte — revisão de código, o histórico dos mantenedores, quantas
> pessoas independentes já leram o diff — é uma pergunta separada que este
> selo não responde.

This directly matches `02-reproducible-builds.md` §4's own framing (it
states the distinction exists; this is the copy that carries it to the
user) and must ship alongside the badge wherever it's rendered, the same
way the pmOS disclosure ships above the fold rather than behind a link.

### 3b. "Verified" today means "Postern's own CI witnessed it," not "independently reproduced by third parties"

`02-reproducible-builds.md` §5's attestation record has a `run.run_by`
field — today, necessarily, a Postern CI identity. The two-independent-
builder-hosts check in the pipeline (`02` §1b step 2) rules out a
single-machine fluke, but **both builders are Postern-operated hosts**. This
is a meaningfully weaker claim than the "many independent eyes" ideal some
reproducible-build efforts aspire to (Debian's Reproducible Builds project,
or F-Droid's own framing when it highlights an app as independently
verified) — where parties *outside* the publisher rebuild and confirm.
State the honest distinction in the badge's fuller documentation (not
necessarily the one-line tooltip, but wherever a user can click through for
detail):

> Today, "ATTESTED" means Postern's own build infrastructure independently
> rebuilt this artifact on two separate machines it operates and confirmed
> both match the published binary and each other. It does not yet mean a
> party outside Postern has reproduced the build. The verifier's build
> recipe and comparison tooling are designed to be runnable by anyone (see
> `02-reproducible-builds.md`), which is what would let a third party
> actually check this claim themselves — but no such independent
> verification is claimed or implied until someone outside Postern has
> actually done it and published the result.

This also answers 02's open question directly: don't blur CI-witnessed into
third-party-reproduced. Say which one it is, every time, and treat
third-party reproduction as a future strengthening to disclose loudly when
it happens, not a thing to imply exists today.

### 3c. Self-hosted repos mean the client must pin/trust keys — restated as a limit, not just a mechanism

§2b–2e above describe the mechanism; stated as a *limit*: **the security of
any third-party repo is only as good as the user's own diligence in
verifying the out-of-band fingerprint when they added it, and Depot has no
mechanism to retroactively improve a badly-verified pin.** A user who adds a
repo from an untrusted link has pinned an untrusted key — cryptography
correctly enforces "unmodified since pinned," which is worthless protection
if what was pinned was already the attacker's key. This is not a flaw
specific to this design; it is the honest ceiling of any TOFU-avoiding
pinning scheme, and it is the same ceiling F-Droid's own alternative-repo
feature has always had. State it rather than let the presence of
cryptography imply a stronger guarantee than "tamper-evidence from the
moment you added it," which is what it actually is.

### 3d. Build attestation is not device attestation

`02-reproducible-builds.md` §4 already states this and cross-references
`os/attested.nix`; restated here because it belongs in the same honesty
register as the rest of this section, not buried in the verifier doc alone:
a PASS from the reproducible-build pipeline is a claim about an artifact
sitting in a repo — it says nothing about what a specific device is
actually running right now. That is the dm-verity + measured-boot +
TPM2/SEV-SNP chain's job. **A complete "you can trust what's on your
phone" claim needs both layers** — the build-reproducibility guarantee this
design adds, and the device-attestation guarantee `os/attested.nix` already
provides for the sealed image tier — and the badge copy must never conflate
"this artifact is provably correct" with "your device is provably running
it," because today only `attestable-nix` apps baked into the sealed image at
build time get the second guarantee at all (`01-architecture.md` §6's
"attestable-nix install gap" — there is no runtime-installed app that also
carries a live device-attestation claim yet).

### 3e. No revocation list, anywhere in this stack

Worth stating once, plainly, because it's true at every layer discussed
across all three documents: apk has no CRL (`pmos-overlay/KEYS.md` §5,
"revocation is out-of-band + a fast key roll"); the near-term Depot index
signature has the same shape of gap (§2d above); and TUF, when it lands,
improves *rotation* ergonomics but still relies on a root role's
availability and correct operation, not a magic revocation channel. Nothing
in this design should be worded to suggest a compromised key can be
instantly and automatically neutralized for every already-pinned client.

---

## 4. How this makes the "attestable" badge real

Tying the three documents together, concretely, this is the mechanism the
task set out to build, stated as a chain of dependencies:

1. **Today:** `attestable` is a tier-eligibility claim only. `normalizeEntry`
   strips the tag from anything not `tier: attestable-nix`, but nothing
   checks whether a specific artifact was actually verified — every app,
   including all six `attestable-nix` entries, sits at
   `signing.state: "unpublished"`.
2. **`02` adds the missing fact-check:** a real build-and-diff pipeline that
   rebuilds from pinned source in Nix's hermetic sandbox, on independent
   hosts, and diffs the result against the shipped artifact. Its output is
   one attestation record per version, with an unambiguous `PASS`/`FAIL`
   verdict — never a fabricated or assumed pass.
3. **`01` adds the place that record lives and how it's checked:** the
   `postern.catalog/v1` schema is extended with `versions[].reproducible_build`,
   the client requires a real `PASS` record (not just the tier string) before
   rendering `ATTESTED`, and the whole index carrying that record is itself
   signed (Ed25519-detached, generalized to per-repo pinned keys) so the
   record can't be forged by tampering with the served JSON either.
4. **`03` (this doc) makes sure the whole pipeline can exist without
   contradicting Postern's own license policy**, and states — in the badge's
   own copy, not just internal design docs — exactly what the resulting
   PASS does and doesn't mean, so the badge, once real, doesn't overclaim
   the moment it stops being aspirational.

The net effect: **ATTESTED goes from "this app's tier says it could be
verified" to "this specific version's binary was independently rebuilt from
its pinned source in a hermetic sandbox, matched itself across independent
hosts, matched the shipped artifact, and that result is carried in a
list whose authenticity is cryptographically checked in-page."** That is a
real mechanism, not a concept — with the honest limits of §3 attached to it
explicitly, not implied away.

---

## 5. Buildable now vs. hard

| Piece | Buildable now, with what exists today | Genuinely hard / open |
|---|---|---|
| Depot index schema extension (`01` §1) | Yes — additive, backward-compatible fields on `postern.catalog/v1`; no migration needed for today's `catalog.json`. | — |
| Per-repo Ed25519 signature + add-by-URL-and-key (`01` §2) | Yes — direct generalization of the exact scheme already shipped in `SIGNING.md`. | Key rotation/revocation UX (§2d) — real gap, needs TUF to close properly. |
| Multi-repo client, honesty-spine enforcement per repo (`01` §3) | Design is concrete; implementation is a client-side feature (persistent repo list, per-repo trust state) not yet built. | Id-collision UX at scale, once real third-party repos exist — the rules are specified but untested against real adversarial listings. |
| postmarketOS install path (`01` §5) | Yes, mechanically — reuses `apk`/`@`-tag/repository-pinning unmodified. | Nothing new; inherits `pmos-overlay`'s own unresolved prerequisites (stable release key not yet generated, no apk has ever actually been built — `pmos-overlay/HONESTY.md`). |
| `attestable-nix` runtime install (`01` §6) | No. | Real, unresolved: the sealed-image model has no clean "install one more attestable app" story yet. Flagged, not solved, by design. |
| First-party verifier pipeline (Rust crates via existing flake, `02` §1a) | Yes — the Nix expressions already exist; wiring the build-twice/diff/compare pipeline around them is new but straightforward given Nix's hermetic guarantees. | Ensuring `cargo build --release` truly disables incremental compilation and other Rust-specific hazards (`02` §4) needs verification, not just assertion. |
| Third-party verifier pipeline via nixpkgs (KeePassXC/Syncthing/GIMP, `02` §1a) | Yes, in principle — pin `flake.lock`, invoke `nixpkgs#<pkg>`. | Whether nixpkgs' own derivations for these are actually bit-reproducible today needs to be *measured*, not assumed — nixpkgs' own reproducibility coverage is strong but not universal. |
| Nix-vs-published-artifact diff (`02` §1b step 5) | Yes, mechanically (hash comparison). | Requires an actual publish pipeline that ships the *exact* Nix-built artifact with no post-build repackaging step — needs to be verified true of `os/attested.nix`'s current image-assembly path, not assumed. |
| Attestation-record signing (`02` §5 `signature` block) | No — placeholder only. | PQ hybrid signing (Falcon-1024‖ML-DSA-65) exists today only for Consiglio login; wiring it to sign build-attestation records, plus chain-anchoring, is unbuilt Depot/TUF-era work. |
| AGPL resolution (`03` §1) | Yes — this is a policy decision, not an engineering task; it's resolved now (clean reimplementation, no `fdroidserver` code in any form). | The reimplementation effort itself (a small but real amount of original code) is unbuilt. |
| Badge honesty copy (`03` §3) | Yes — the copy is drafted above and can ship as soon as there's a real badge to attach it to. | Keeping it accurate as the pipeline matures (e.g., the moment third-party reproduction becomes real, §3b's wording must change too) requires discipline, not new invention. |
| TUF + PQ + chain-anchored Depot (the full target state in `SIGNING.md`) | No. | This is explicitly the acknowledged "later" tier across all three docs — Ed25519-per-repo is the honest, real, near-term step; TUF/PQ/chain-anchoring is the named destination, not yet started. |

The overall shape: **the repo/client/schema layer (`01`) and the AGPL
resolution (`03` §1) are close to buildable as specified.** The verifier
(`02`) is buildable for the first-party apps with moderate new work, and
plausible-but-unverified for the third-party nixpkgs-based apps until
someone actually measures nixpkgs' reproducibility for those specific
packages. The two hardest unresolved problems, named plainly rather than
smoothed over, are the **`attestable-nix` runtime-install gap** (`01` §6)
and **key rotation/revocation without TUF** (`03` §2d) — both are real
architectural tensions this design surfaces rather than resolves, and both
should be treated as prerequisites to recommending Depot broadly, the same
way `pmos-overlay/PUBLISHED.md` already treats "adopt a stable signing key"
as a prerequisite before recommending that repo broadly.
