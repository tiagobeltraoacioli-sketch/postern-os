# Bitcointalk post — Bloch-SIS-PoW public testnet (draft)

> **Posting note (read before posting).**
> Recommended board: **Development & Technical Discussion**
> (acceptable alternative: **Project Development**).
> Do **NOT** post this in *Announcements (Altcoins)* and do **not** format it as an
> `[ANN]` thread. This is a research testnet seeking technical reviewers and
> testers — it is not a coin launch, there is nothing to buy, and framing it as
> an announcement of a tradable coin would misrepresent it. The dev boards are
> where PoW-design and consensus discussion actually gets read by the people we
> want to hear from.
>
> Bitcointalk uses **BBCode**, not Markdown. A ready-to-paste BBCode version is
> at the bottom of this file. The Markdown version is for review only.

---

## Suggested thread title

```
[TESTNET] Bloch-SIS-PoW — post-quantum PoW BlockDAG (SHAKE-256 hashcash PoW with a Module-SIS gate, Falcon‖ML-DSA) — seeking testers/reviewers, coins worthless by design
```

---

## Body (Markdown review copy)

**Bloch-SIS-PoW** is an experimental **post-quantum, pure proof-of-work BlockDAG
Layer-1** whose proof-of-work is a **SHAKE-256 hashcash** with a **Module-SIS**
(Short Integer Solution) **structural gate** — a lattice-form residual filter
derived from the block header that binds the work to a lattice shape but is
**not** the security source (security is cumulative hash work). We have just
opened a **public testnet** and are looking for people to run nodes, try to
break things, and — above all — review the PoW design.

> ### ⚠ READ THIS FIRST — honest status (the part that matters)
>
> - This is a **public TESTNET of experimental research software**. There is
>   **no mainnet** and no mainnet date.
> - The Module-SIS PoW currently runs a **relaxed, trivially forgeable testnet
>   regime** (the residual bound is checked on only a handful of coefficients so
>   blocks can be brute-force mined). It provides **zero security**. **Anyone
>   can forge work and mint unlimited coins.** The coin is therefore **worth
>   nothing, by design and by declaration**.
> - The coin is **not a security and not an asset**. There is **no token sale,
>   no listing effort, no market-making, and no price** — past, present, or
>   planned. Please do not attach value to it, and do not ask us to.
> - Disclosed in full so nobody discovers it later: the genesis allocates a
>   **17% founder premine** (10-year cliff, then 40-year monthly on-chain
>   vesting), structurally passive — no governance power, no protocol
>   privileges, zero sale, zero listing effort.
> - The code is **unaudited**. Mainnet is gated on (a) a concrete-security
>   analysis of the canonical PoW parameters (lattice-estimator class), (b) an
>   IACR ePrint for open expert review, and (c) a third-party audit.
>   **None of these has been done.**
> - Participation means **helping test experimental post-quantum PoW
>   research** — not mining, holding, or buying anything of value. If you are
>   here for a coin, this thread has nothing for you.

### What it is

- **Consensus:** PHANTOM/GhostDAG-Q BlockDAG, pure PoW, no BFT finality, no
  validator set, no treasury — finality is PoW depth, à la Bitcoin/Kaspa.
  30-second target block time, per-block ASERT-Lattice difficulty.
- **Proof-of-work:** **Bloch-SIS** — given a serialized header and nonce, the
  miner must find a short vector `s ∈ {-B,…,B}^N` with `‖A·s − t‖_∞ < β`, where
  the Module-SIS instance `(A, t)` is derived from the header via SHAKE-256,
  **and** an auxiliary SHAKE-256 hash of `s` must meet the difficulty target.
  Verification is cheap. The Module-SIS residual is a fixed structural
  rejection filter, not the security source — block-production security is the
  cumulative hashcash work on the aux target (our estimator research showed a
  trapdoorless PoW cannot be both lattice-hard and mineable). The current
  testnet regime relaxes the residual check to a few coefficients, which is
  exactly why the testnet is insecure and the coins are worthless.
- **Signatures:** hybrid **Falcon-1024 ‖ ML-DSA-65** — both must verify, two
  distinct lattice families.
- **Transport:** libp2p gossipsub + IBD sync, with an ML-KEM-768 hybrid
  handshake and hybrid PQ peer identity.
- **Storage:** RocksDB. Written in Rust.

### What we think is novel (and want challenged)

Post-quantum on **every consensus-critical primitive** — not just the
signatures. The PoW (SHAKE-256 hashcash, Grover-bounded, with a Module-SIS
structural gate), the signatures (Falcon + ML-DSA), and the seed/aux hashing
(SHAKE-256) are all PQ; there is no classical primitive on the consensus path.
We state the negative result up front: our estimator research found that a
trapdoorless PoW **cannot** be parameterized to be simultaneously lattice-hard
and mineable (the regimes are disjoint), so we make **no lattice bit-security
claim for the PoW**. The interesting open question — and the reason this
thread is on a dev board — is the **no-shortcut claim** for the small-`k` SIS
gate: can lattice reduction (or anything else) give an attacker asymmetric
advantage over honest brute-force at the canonical gate width? We do not claim
that proof; we claim a running testbed for it.

### What is explicitly NOT done

- Canonical gate parameters with a no-shortcut analysis — **not done**
  (the testnet regime is deliberately forgeable).
- IACR ePrint write-up — **not done**.
- Third-party audit — **not done**.
- Pool mining — **disabled** (Stratum has no field for a lattice solution
  vector; a SIS-native share protocol is future work). Solo `--mine` only.

### How to join the testnet

The protocol is ownerless — no foundation, no official website, no privileged
seed nodes (the shipped seed list is literally empty). The repository:

```
gitlab.com/blochsispow-group/BlochSISPoW-project
```

Quick start (Rust toolchain + clang/cmake required):

```
git clone <the repository above> bloch && cd bloch
cargo build --release
./target/release/bloch --testnet --data-dir ./bloch-data \
    --listen /ip4/0.0.0.0/tcp/16110 --peer <multiaddr-of-any-testnet-peer>
# add --mine to solo-mine (worthless) testnet blocks
# check it's up:  ./target/release/bloch-cli getnetworkinfo   (RPC on 127.0.0.1:16210)
```

Because there are no privileged seeds, you bootstrap from **any** existing
testnet peer's `--listen` multiaddr (post yours in this thread), or start your
own island network. A full step-by-step tutorial ("Run a node") is on the
Postern Labs site; the same content ships with the product repo, and the
commands above are self-sufficient.

### What feedback we're looking for

1. Attacks on the PoW design (grinding, amortization, precomputation,
   progress-freeness, verify/mine asymmetry) — even against the canonical
   regime on paper.
2. Consensus/DAG edge cases: reorgs, timestamp games, difficulty (ASERT-Lattice)
   manipulation.
3. Networking/IBD breakage, RPC issues, build failures on your platform.
4. "This was tried in [paper X] and fails because Y" — the most valuable reply
   of all.

Disclosure of interest: I build products on top of this protocol (Postern
Labs), but the protocol itself has no owner and I hold no privileged role in
it beyond the disclosed premine above. Everything here is MIT/Apache-2.0.

**Please do not post price, market, exchange, or "when mainnet" talk in this
thread — there is no price, there will be no listing effort, and mainnet is
gated on research that is not done.** Peer multiaddrs, build reports, and
attacks are all very welcome.

— Tiago Tenório (TT)

---

## BBCode version (paste this into Bitcointalk)

```bbcode
[b]Bloch-SIS-PoW — an experimental post-quantum, pure-PoW BlockDAG L1. Public testnet is open; seeking testers and reviewers.[/b]

Its proof-of-work is a [b]SHAKE-256 hashcash[/b] with a [b]Module-SIS[/b] (Short Integer Solution) [b]structural gate[/b] — a lattice-form residual filter derived from the block header that binds the work to a lattice shape but is [b]not[/b] the security source (security is cumulative hash work). We just opened a public testnet and are looking for people to run nodes, break things, and review the PoW design.

[quote]
[size=12pt][b]⚠ READ THIS FIRST — honest status[/b][/size]

[list]
[li]This is a [b]public TESTNET of experimental research software[/b]. There is [b]no mainnet[/b] and no mainnet date.[/li]
[li]The Module-SIS PoW currently runs a [b]relaxed, trivially forgeable testnet regime[/b] (the residual bound is checked on only a handful of coefficients so blocks can be brute-force mined). It provides [b]zero security[/b]. [b]Anyone can forge work and mint unlimited coins[/b] — the coin is [b]worth nothing, by design and by declaration[/b].[/li]
[li]The coin is [b]not a security and not an asset[/b]. [b]No token sale, no listing effort, no market-making, no price[/b] — past, present, or planned. Do not attach value to it.[/li]
[li]Disclosed in full: the genesis allocates a [b]17% founder premine[/b] (10-year cliff, then 40-year monthly on-chain vesting), structurally passive — no governance power, no protocol privileges, zero sale, zero listing effort.[/li]
[li]The code is [b]unaudited[/b]. Mainnet is gated on (a) a concrete-security analysis of the canonical PoW parameters, (b) an IACR ePrint for open expert review, and (c) a third-party audit. [b]None of these has been done.[/b][/li]
[li]Participation means [b]helping test experimental post-quantum PoW research[/b] — not mining, holding, or buying anything of value.[/li]
[/list]
[/quote]

[b]What it is[/b]
[list]
[li][b]Consensus:[/b] PHANTOM/GhostDAG-Q BlockDAG, pure PoW — no BFT finality, no validator set, no treasury. Finality is PoW depth, à la Bitcoin/Kaspa. 30 s target block time, per-block ASERT-Lattice difficulty.[/li]
[li][b]Proof-of-work:[/b] [b]Bloch-SIS[/b] — from a serialized header + nonce, the miner must find a short vector s ∈ {-B,…,B}^N with ‖A·s − t‖_∞ < β, where the Module-SIS instance (A, t) is derived from the header via SHAKE-256, [b]and[/b] an auxiliary SHAKE-256 hash of s must meet the difficulty target. Verification is cheap. The Module-SIS residual is a fixed structural rejection filter, not the security source — block-production security is the cumulative hashcash work on the aux target (our estimator research showed a trapdoorless PoW cannot be both lattice-hard and mineable). The current testnet regime relaxes the residual check to a few coefficients — which is exactly why the testnet is insecure and the coins are worthless.[/li]
[li][b]Signatures:[/b] hybrid [b]Falcon-1024 ‖ ML-DSA-65[/b] — both must verify; two distinct lattice families.[/li]
[li][b]Transport:[/b] libp2p gossipsub + IBD sync, ML-KEM-768 hybrid handshake, hybrid PQ peer identity.[/li]
[li][b]Storage:[/b] RocksDB. Written in Rust.[/li]
[/list]

[b]What we think is novel (and want challenged)[/b]

Post-quantum on [b]every consensus-critical primitive[/b] — not just the signatures. The PoW (SHAKE-256 hashcash, Grover-bounded, with a Module-SIS structural gate), the signatures (Falcon + ML-DSA), and the seed/aux hashing (SHAKE-256) are all PQ; no classical primitive sits on the consensus path. We state the negative result up front: our estimator research found a trapdoorless PoW [b]cannot[/b] be parameterized to be simultaneously lattice-hard and mineable, so we make [b]no lattice bit-security claim for the PoW[/b]. The open question — and the reason this is on a dev board — is the no-shortcut claim for the small-k SIS gate: can lattice reduction (or anything else) give an attacker asymmetric advantage over honest brute-force at the canonical gate width? We do not claim that proof; we claim a running testbed for it.

[b]What is explicitly NOT done[/b]
[list]
[li]Canonical gate parameters with a no-shortcut analysis — [b]not done[/b] (the testnet regime is deliberately forgeable).[/li]
[li]IACR ePrint write-up — [b]not done[/b].[/li]
[li]Third-party audit — [b]not done[/b].[/li]
[li]Pool mining — [b]disabled[/b] (Stratum has no field for a lattice solution vector; a SIS-native share protocol is future work). Solo --mine only.[/li]
[/list]

[b]How to join the testnet[/b]

The protocol is ownerless — no foundation, no official website, no privileged seed nodes (the shipped seed list is literally empty). Repository:

[code]gitlab.com/blochsispow-group/BlochSISPoW-project[/code]

Quick start (Rust toolchain + clang/cmake required):

[code]git clone <the repository above> bloch && cd bloch
cargo build --release
./target/release/bloch --testnet --data-dir ./bloch-data \
    --listen /ip4/0.0.0.0/tcp/16110 --peer <multiaddr-of-any-testnet-peer>
# add --mine to solo-mine (worthless) testnet blocks
# check it's up:  ./target/release/bloch-cli getnetworkinfo   (RPC on 127.0.0.1:16210)[/code]

There are no privileged seeds, so you bootstrap from [b]any[/b] existing testnet peer's --listen multiaddr — post yours in this thread — or start your own island network. A full step-by-step "Run a node" tutorial is on the Postern Labs site, and the commands above are self-sufficient.

[b]Feedback we're looking for[/b]
[list=1]
[li]Attacks on the PoW design (grinding, amortization, precomputation, progress-freeness, verify/mine asymmetry) — including on-paper attacks against the canonical regime.[/li]
[li]Consensus/DAG edge cases: reorgs, timestamp games, ASERT-Lattice difficulty manipulation.[/li]
[li]Networking/IBD breakage, RPC issues, build failures on your platform.[/li]
[li]"This was tried in [paper X] and fails because Y" — the most valuable reply of all.[/li]
[/list]

Disclosure of interest: I build products on top of this protocol (Postern Labs), but the protocol itself has no owner and I hold no privileged role in it beyond the disclosed premine above. Everything is MIT/Apache-2.0.

[b]Please keep price, market, exchange, and "when mainnet" talk out of this thread[/b] — there is no price, there will be no listing effort, and mainnet is gated on research that is not done. Peer multiaddrs, build reports, and attacks are all very welcome.

— Tiago Tenório (TT)
```
