# Postern Enterprise — corporate identity, information barriers & lifecycle (design spec)

**Product (Postern Labs). Status: design + reference console.**
The enterprise/corporate architecture for the Postern OS family (Linux desktop +
mobile): access hierarchy, Personal-vs-Corporate licensing, Brewer–Nash
information barriers ("Chinese Walls"), machine segmentation, succession and
offboarding, and the technical controls that **enable** — never certify —
compliance programs under LGPD (Brazil), GDPR (EU), CCPA/CPRA (California) and
similar regimes.

> Reference console: `apps/postern-enterprise/index.html` (codename
> **Consiglio** — the council; governance here is a quorum, not a person).
> It demonstrates the org/role model, the Chinese-Wall segment editor, the
> provision/offboard ceremonies with dual-control escrow, the tamper-evident
> audit chain, and the employee-facing transparency panel.

---

> ## ⚠ NOT LEGAL ADVICE — read this first
>
> **This document is a technical architecture, written by engineers. It is not
> legal advice, and nothing in it certifies or promises compliance with LGPD,
> GDPR, CCPA/CPRA, or any other law.** Actual compliance is a *legal and
> organizational* outcome that requires, at minimum: a qualified **DPO /
> Encarregado** (mandatory in many LGPD/GDPR contexts), **legal counsel**
> admitted in each relevant jurisdiction, documented lawful bases, records of
> processing, DPIAs where required, contracts (DPAs) with processors, and
> decisions this document deliberately does **not** make (retention periods,
> lawful basis per purpose, cross-border transfer mechanisms,
> breach-notification triggers and timelines, employee-consultation duties
> under local labor law).
>
> Throughout this spec, every such point is flagged inline as
> **LEGAL DETERMINATION REQUIRED (DPO/counsel)**. The correct sentence is
> always *"this control supports requirement X; the legal determination is
> counsel's"* — never "this is compliant." Any Postern material that says
> "compliant" without that qualification is wrong and should be fixed.

---

## 1 · Two licenses, two trust models — Personal vs Corporate

Postern ships the Desktop OS and the Mobile OS in **two formats each** (four
SKUs). The *software* is largely the same; the **root of identity and the
recovery/authority model differ by design**, and the difference is stated to
the user in plain words at setup.

| Dimension | **Personal license** (Desktop / Mobile) | **Corporate license** (Desktop / Mobile) |
|---|---|---|
| Root of identity | The user's **self-custody wallet** (Chiave, `POSTERN-IDENTITY.md`): BIP39 seed → hybrid Falcon-1024 ‖ ML-DSA-65, sealed in the TEE. | An **org-provisioned account** bound to the company directory. The device keypair still lives in the user's device TEE, but it is *certified by the org*, not self-sovereign. |
| Who is the identity authority | The user, alone. No server, no admin. | The **company** (data controller). It provisions, certifies, and can revoke. |
| Recovery | **Seed phrase or nothing** — no reset flow exists, stated plainly. | **Escrowed recovery under dual control** (§3.4): an M-of-N governance quorum can restore access or recover *company* data. No single admin can. |
| Revocation | Impossible by anyone but the user (erase device). | **Instant deprovision** by the org: directory assertion stops, volume keys stop being released, sessions are killed (§6.2). |
| Directory | None. Peer identities are derived keys (`m/app/<name>`). | A **directory of record**: self-hosted Postern Directory, or federation to the org's existing IdP via **OIDC / SAML** (§3.2). |
| Policy | The user's own. Optional *transparent* managed-device policy (Sarto) if the user enrolls a guardian/admin — always visible, never covert. | **Org policy is mandatory on the org's device** — signed, versioned, and always visible to the employee in the transparency panel (§8). |
| Admin | There is no admin. | An **admin-of-record** (named, fingerprinted) + a governance quorum. Sensitive powers (escrow release, data access) need **M-of-N approval + tamper-evident audit** (§3.4, §7). No silent super-admin exists, by refusal. |
| Data controller | The user. | The **company** — with the controller obligations that follow (§9). |
| Monitoring | None. | **Declared** device-inventory/posture/policy telemetry only, listed item-by-item in the transparency panel. No covert monitoring mode exists in the codebase (§8). |

**What does *not* change:** the crypto stack (hybrid PQ signatures, TEE-sealed
keys, FBE/LUKS volumes, `postern-vault`, Panic Lock for personal spaces),
privacy-by-default networking, the metadata-hygiene posture, and the refusal
to build covert modes.

**An employee's *personal* Postern identity is out of the org's reach.** On a
corporate device there is no personal wallet by default; if the org permits a
personal *space* (mobile dual-persona, §5.3), it is a separate encrypted
profile whose keys the org never holds and whose contents the org's policy
engine cannot read — mirroring, in reverse, the Android work-profile boundary
(`POSTERN-CONTAINER.md`).

## 2 · The ethos tension, stated honestly

Postern's personal products are built on self-sovereignty: *your* key, no
admin, no recovery authority. The corporate product **necessarily trades some
of that away**, and we say so instead of hiding it:

- The company **owns the device** and is the **data controller** for the work
  done on it. It can provision, revoke, and — under quorum — recover company
  data. An employee on a corporate device is *not* self-sovereign over that
  device. That is the honest deal of employment equipment everywhere; Postern
  does not pretend otherwise.
- What Postern refuses to trade: **transparency** (every power the org has is
  displayed to the employee; no covert mode exists), **proportionality**
  (data minimization by default — the org gets posture and policy state, not
  keystrokes or content), **dual control** (no single admin can silently read
  or impersonate), and **auditability** (every sensitive act lands in a
  tamper-evident log the compliance function can inspect).
- LGPD Art. 6 / GDPR Arts. 5, 13–14 themselves push in this direction:
  transparency and minimization toward employees are not merely ethical
  preferences here — they are what the law expects of an employer-controller.
  **LEGAL DETERMINATION REQUIRED (DPO/counsel):** the lawful basis and the
  permissible scope of *any* employee monitoring vary sharply by jurisdiction
  (e.g., consent is generally weak in employment contexts; works-council or
  union consultation may be mandatory; Brazil and EU member states add labor
  law on top of privacy law).

## 3 · Corporate identity — the cryptographic model

Corporate login is **not** the self-custody wallet. It reuses Chiave's
*machinery* (TEE-held signing keys, challenge ceremony, domain-separated
derivation) under a different authority model.

### 3.1 Keys and certificates

| Key | Held by | Purpose |
|---|---|---|
| **Org root key** (hybrid Falcon-1024 ‖ ML-DSA-65) | Offline / HSM; usable only under governance quorum (§3.4) | Root of the org's identity. Signs the directory signing key and the governance-quorum public set. Rotated rarely, ceremonially. |
| **Directory signing key** | The directory service (self-hosted Postern Directory) or delegated to the federated IdP trust anchor | Signs **enrollment certificates** and **short-lived login assertions**; signs policy documents (with the admin-of-record countersignature). |
| **Per-user device key** (hybrid, per device) | The **employee's device TEE**, non-exportable — same StrongBox / Secure Enclave / measured-boot sealing as Chiave | Signs the login challenge. Generated *on the device* at enrollment; the private half never leaves the TEE — the org certifies it, it does not hold it. |
| **User data keys** (FBE/volume KEKs, vault key) | Derived on device per §3.3, released only during a valid session | Encrypt the user's corporate profile and the project volumes they are entitled to (§5). |
| **Escrow recovery key** (per user) | **Nobody, whole.** Split M-of-N (Shamir) across the governance quorum (§3.4) | The org-side recovery path for *company* data and account restore. |

### 3.2 Enrollment and login

1. **Provisioning** (admin action, audited): the admin-of-record creates the
   directory entry — name, org unit, role, attributes (§4) — and issues a
   one-time enrollment token (QR / code, short TTL, single use).
2. **Enrollment** (on the employee's device): the device generates a fresh
   hybrid keypair in the TEE; sends the public key + Postern Seal attestation
   evidence (`os/ATTESTATION.md`: measured boot, genuine build) to the
   directory; the directory verifies the attestation and issues an
   **enrollment certificate**: `sign(directory_key, {user_id, device_id,
   device_pubkey, role, attrs, policy_version, not_after})`.
3. **Login** is Chiave's ceremony with one added verifier: unlock the
   TEE-gated device key locally (passphrase/biometric — biometric rules are
   identical to `POSTERN-IDENTITY.md`), sign the fresh challenge, **and**
   present a **short-lived directory assertion** (minutes-to-hours TTL,
   OIDC-token-like). The OS session opens only if *both* verify: the device
   proves "this is the enrolled hardware + user", the directory proves "the
   org still vouches for this account *right now*."
4. **Revocation = the assertion stops.** Because assertions are short-lived,
   deprovisioning takes effect within one TTL even if the revocation push is
   missed; the push makes it immediate (§6.2). Offline grace (how long a
   device may work without reaching the directory) is **org policy, visible
   to the employee** — and bounded, because every volume-key release (§5)
   rechecks entitlement.
5. **Federation:** instead of the self-hosted Postern Directory, the org may
   federate to its existing IdP via **OIDC or SAML**. The IdP then answers
   "is this account active, what groups/attributes" — but the *device key
   still lives in the TEE* and the challenge ceremony still runs locally;
   federation replaces the assertion issuer, not the device-bound crypto.
   Honest note: federating imports the IdP's failure and phishing surface —
   the device-key check is what keeps a stolen IdP session from becoming a
   Postern session.

### 3.3 Data keys — corporate derivation

Personal Postern derives everything from the user's seed. Corporate Postern
derives the user's *corporate* data keys from a **device-TEE random root**
(not a user-memorable seed — there is deliberately no user-exportable seed for
corporate data), with the same domain-separation discipline:

- `corp/profile` → FBE class keys for the user's corporate home profile;
- `corp/vault` → the user's corporate `postern-vault` KEK (work app secrets);
- **project volume keys are NOT user-derived** — they belong to the volume
  and are *wrapped to* entitled users (§5.2), so entitlement changes never
  require re-encrypting data, only re-wrapping keys.

At enrollment, the data root is additionally **wrapped under the user's
escrow recovery key** (§3.1), producing the escrow record. That is the entire
recovery path: reconstruct the escrow key (quorum), unwrap the data root,
re-seal to a new device or to the successor. Lose quorum + device and
corporate data is as gone as a lost personal seed — stated to the org at
setup, because escrow governance is now *their* seed phrase.

### 3.4 Dual-control escrow — no single silent admin

The design goal: **the org can always recover company data and access, and no
individual can do it alone or invisibly.**

- At org bootstrap, the org names a **governance quorum**: N officers
  (recommended: IT admin, compliance/DPO officer, and an executive; N ≥ 3),
  threshold M (recommended M = 2 for N = 3; larger orgs raise both). Each
  officer holds their own TEE-sealed keypair.
- Each user's **escrow recovery key** is generated at enrollment and
  immediately **split with Shamir secret sharing (M-of-N)**; each share is
  encrypted to one officer's key. The whole key exists only transiently in
  the enrollment ceremony and during an approved release.
- A **release** (recovery, offboarding handover, or a lawful data-access
  request) requires: a stated **purpose** (recorded verbatim), **M distinct
  officer approvals** — each approval is that officer unlocking their own key
  and signing the release record — and lands as a chained entry in the audit
  log (§7) *before* the key material is reconstructed. The employee (or their
  manager, if the employee is gone) is **notified by default**; suppressing
  notification is itself a logged, quorum-approved act.
  **LEGAL DETERMINATION REQUIRED (DPO/counsel):** when notification may or
  must be delayed (e.g., an investigation), and what purposes are lawful
  grounds for accessing an employee's work data, are legal/HR decisions.
- **What escrow cannot do:** it cannot read the employee's *personal* space
  (§5.3) — those keys are never escrowed; and it cannot act without leaving a
  verifiable trail — the audit chain is hash-linked and replicated to the
  compliance officer's custody, so deleting the evidence requires corrupting
  a log the watched party doesn't control. Honest limit: an org that
  colludes at quorum scale *can* access corporate data — that is the stated
  purpose of escrow, not a backdoor; the control is that it cannot happen
  silently, singly, or deniably.

## 4 · Access hierarchy — RBAC + ABAC

Two layers, both mandatory (default-deny):

- **RBAC** — the org tree (org units/departments) and **roles** (e.g.,
  `engineer`, `finance-analyst`, `counsel`, `it-admin`, `compliance-officer`).
  A role is a bundle of **entitlements**: which apps are installed, which
  project volumes *may* be mounted, which network egress classes are open
  (§5.1). Roles follow least-privilege; `it-admin` conspicuously does **not**
  entitle reading user volumes — admin ≠ access, access needs entitlement +
  (for escrowed paths) quorum.
- **ABAC** — attributes on the user (`department`, `clearance`, `project`,
  `region`, contract type) and on the resource (dataset sensitivity, COI
  class §5.2, jurisdiction tag). Policy rules combine them:
  `mount(volume) ⇐ role ∈ volume.roles ∧ user.clearance ≥ volume.clearance ∧
  wall_check(user, volume) = pass`. Attributes are set by the admin, visible
  to the employee, and every change is audited.

Separation-of-duty pairs are declared in policy (e.g., the same person cannot
hold `it-admin` and `compliance-officer`; payment-approval and
vendor-creation roles conflict) and enforced at role assignment.

## 5 · Machine segmentation & the Chinese Wall

### 5.1 Per-role machine profiles

Because Postern OS is **declarative NixOS** (`os/desktop.nix`,
`os/mobile.nix`), a machine profile is literally a Nix expression selected by
role at enrollment: the app set, the mountable volumes, the network egress
classes (e.g., `finance` gets no outbound except the ERP and banking
endpoints through the VPN; `engineer` gets the forges; everyone gets the
directory), and the hardening baseline. Profiles are built reproducibly and
attested (Postern Seal), so the org can *prove* a fleet machine runs the
genuine profile — and the employee can verify the same thing from the
transparency panel. Reprovisioning a machine for a new role is a rebuild, not
a hand-configured drift.

### 5.2 Brewer–Nash information barriers (the Chinese Wall)

For orgs whose duty is *conflict-of-interest separation* (law firms, agencies,
consultancies, M&A desks), RBAC/ABAC is not enough — the wall must depend on
**history**. Postern implements the Brewer–Nash model:

- **Objects** are datasets, materialized as **per-project encrypted volumes**
  (each volume has its own key, wrapped to entitled users' device keys).
- Every dataset belongs to a **company dataset group** (e.g., "Client A"),
  and groups belong to a **conflict-of-interest class** (e.g., "Banking
  clients" containing Client A and Client B, who are competitors).
- **The rule (simple security):** a user may access a dataset in group *g*
  of COI class *c* only if they have **never accessed** a dataset of a
  *different* group in the same class *c*. First access is a free choice;
  it **binds**: touching Client A's data walls you off Client B's, for as
  long as the wall policy says (unbinding is an explicit, audited,
  quorum-approved act — e.g., after a cooling-off period).
  **LEGAL DETERMINATION REQUIRED (counsel):** cooling-off durations and
  wall-crossing approval standards are professional-conduct/legal decisions
  (bar rules, FCA-style requirements), not engineering ones.
- **Enforcement is mandatory, not discretionary:** the wall check runs in the
  volume-key broker — the component that wraps/releases volume keys. A walled
  user's device is *never given the key*; there is no "open anyway" button,
  and neither the user nor their manager can waive it (only the audited
  quorum path). Access *events* (first-touch bindings) are recorded in the
  audit chain, because the model's state *is* that history.
- Brewer–Nash **\*-property** (write rule) honesty: full enforcement — "you
  may write to a dataset only if you can read nothing outside it (bar
  sanitized data)" — is a strong restriction; Postern implements it as a
  per-volume **no-cross-copy** policy (clipboard/file-move between volumes of
  different COI groups is blocked in-session) and flags, rather than
  silently permits, exports from walled volumes.

**The honest limit.** Cryptographic key-withholding is *hard* denial for data
at rest: a walled user's machine mathematically cannot mount the volume. But
once *entitled* data is decrypted in a session, containing it is an OS
problem: hard in-session enforcement needs **OS-level MAC** (SELinux/AppArmor
domains per volume, as the container/hardening layer provides) so that a
process reading volume A cannot write outside A. On Postern OS that MAC layer
is part of the profile; on anything client-side only — including the
reference console, which says so on its face — wall enforcement is
**advisory**: it demonstrates and audits the model, it cannot physically stop
a determined insider. And no OS stops a human photographing a screen:
information barriers are ultimately a *combined* technical + contractual +
supervisory control, which is exactly how Brewer–Nash deployments are
regulated in practice.

### 5.3 Personal space on corporate mobile (dual persona)

If the org enables it, the mobile OS offers a **personal profile** alongside
the corporate one — the mirror image of `POSTERN-CONTAINER.md` (there:
private container on a personal phone; here: personal container on a company
phone). Keys for the personal profile are the employee's own (Chiave model,
never escrowed); org policy can *size* it (storage quota, no corporate data
in, per-profile VPN) but cannot read it. What the org can see about the
personal profile — existence and storage size, nothing else — is listed in
the transparency panel. **LEGAL DETERMINATION REQUIRED (DPO/counsel):** BYOD
and dual-persona arrangements change the controller analysis and may require
specific employee agreements.

## 6 · Lifecycle — onboarding, offboarding, succession

Every step below emits chained audit entries (§7). The controller obligations
in (§9) attach at each step; retention and deletion *periods* are always
policy inputs from counsel, never engineering defaults.

### 6.1 Onboarding

1. Directory entry: identity, org unit, **role**, attributes; transparency
   packet generated (what this role's policy monitors — shown to the
   employee at first login, not buried in a PDF).
2. Enrollment ceremony (§3.2): device TEE keypair + attestation +
   enrollment certificate.
3. **Escrow ceremony** (§3.4): recovery key generated, Shamir-split to the
   quorum, whole key destroyed.
4. Machine profile (§5.1) provisioned; entitled volume keys wrapped to the
   device key (§5.2 wall check runs from day one).
5. Employee sees the transparency panel and acknowledges the policy
   (acknowledgment ≠ consent; **LEGAL DETERMINATION REQUIRED (DPO/counsel):**
   the lawful basis for employment processing is typically *not* consent —
   basis selection and its documentation are counsel's).

### 6.2 Offboarding on termination — the ceremony, in order

1. **Revoke** — directory marks the account terminated: assertion issuance
   stops **immediately**; the revocation push kills active sessions on all
   enrolled devices; volume-key broker stops honoring the user's wrappings.
   Target: seconds, not the assertion TTL.
2. **Freeze, don't peek** — the user's corporate profile and vault stay
   sealed. Nobody, including IT, gains read access by termination itself.
3. **Escrow-governed handover** — with a stated purpose and M-of-N approval
   (§3.4), the quorum reconstructs the escrow key, unwraps the *corporate*
   data root, and re-seals selected company data to the **successor or
   manager**. The scope of the handover (which volumes, which mailboxes) is
   part of the approval record.
4. **Rotate** — every shared volume key the departed user was wrapped to is
   rotated (new key, re-wrapped to remaining entitled users); shared
   secrets/credentials in their reach are rotated per an inventory the role
   profile already knows (that's what entitlements are for).
5. **Wipe or reprovision** the device: cryptographic erase of the corporate
   profile (destroy the TEE-held keys — instant, verifiable) and either
   fleet-return reprovisioning or, for dual-persona phones, corporate-profile
   removal that leaves the personal profile untouched.
6. **Retention & the departed employee's personal data** — HR/directory
   records, audit entries naming them, and any content in the handed-over
   data that is *their* personal data are handled per the org's retention
   schedule and data-subject-rights process.
   **LEGAL DETERMINATION REQUIRED (DPO/counsel):** retention periods,
   the balance between erasure rights and legal hold/labor-litigation needs
   (in Brazil, e.g., labor-claim limitation periods), and what must be
   deleted vs anonymized are legal decisions; Postern provides the secure-
   deletion and export mechanics (§9), not the schedule.

### 6.3 Succession / replacement

The successor **inherits the role**, not the person: assigning the role
re-runs entitlement wrapping (and the wall check — a successor who is walled
from a COI group does *not* inherit that group's volumes; the conflict
surfaces immediately and loudly instead of silently). The handover of the
predecessor's data is only ever the §6.2-step-3 quorum path, so the audit
trail reads: who approved, what scope, to whom, when. Role changes for a
continuing employee (promotion/transfer) are the same machinery: entitlements
diff → wrap/unwrap → profile rebuild → audit.

## 7 · Audit — tamper-evident, two-custody

- Every sensitive event (provision, role/attribute change, wall binding,
  escrow approval/release, revocation, wipe, policy change) is an entry in a
  **hash-chained log**: `hash_i = H(canonical(entry_i) ‖ hash_{i-1})`, entries
  signed by the acting component, chain heads periodically countersigned by
  the **compliance officer's** key and replicated outside IT's custody —
  tampering requires breaking both custodies, and verification is a
  chain-walk anyone entitled can run (the console demonstrates it).
- Logs are **about administrative and security events, not employee
  content** — data minimization applies to the audit trail too. What the log
  records about a user is listed in the transparency panel.
- **LEGAL DETERMINATION REQUIRED (DPO/counsel):** audit-log retention, and
  the fact that audit logs are themselves personal data of employees
  (LGPD/GDPR apply to them), need a documented basis and schedule.

## 8 · Transparency to the employee — non-negotiable

Every corporate device shows a permanent, unremovable **transparency panel**
(the Sarto pattern, `apps/postern-onboard`): who manages the device (org +
admin-of-record, key fingerprints), the governance quorum, the policy version
(signed; signature failure renders in red), the machine profile, **exactly
what telemetry leaves the device** (inventory, posture, policy state, audit
events — itemized) and **what does not** (keystrokes, screen contents, file
contents, personal-profile anything, location unless the org enables
lost-device mode — in which case *that* is listed too), their wall bindings,
and the escrow-notification promise (§3.4). There is no covert mode: not
disabled, **absent** — a policy that isn't shown isn't enforced. This is both
the product's ethics and the direction of LGPD Arts. 9/18 and GDPR Arts.
12–14 transparency duties toward employees;
**LEGAL DETERMINATION REQUIRED (DPO/counsel):** the *content* of the
employee privacy notice and local consultation duties.

## 9 · Compliance-ENABLING control map — NOT legal advice

> **Disclaimer, again, on purpose:** this table maps Postern's technical
> controls to *requirement areas* of LGPD, GDPR, and CCPA/CPRA. It does not
> assert compliance with any of them. Other regimes (PIPEDA, UK GDPR, APPI,
> state laws beyond California, sectoral rules like HIPAA/BACEN/CVM) **vary —
> counsel required.** For every row: *the control supports the requirement
> area; the legal determination is counsel's.*

| Requirement area (LGPD / GDPR / CCPA-CPRA) | Technical control Postern provides | LEGAL DETERMINATION REQUIRED (DPO/counsel) |
|---|---|---|
| **Data-subject / data-holder rights: access & portability** (LGPD Art. 18 II, V; GDPR Arts. 15, 20; CCPA right to know) | Per-user encrypted profiles make "what we hold on/about this person" enumerable; structured **export** of a user's directory record, attributes, audit entries naming them, and profile data (machine-readable). | Which requests must be honored, in what scope/format/deadline (15 days LGPD, 1 month GDPR, 45 days CCPA — verify per case), identity-verification standard, and employment-context carve-outs. |
| **Deletion / erasure** (LGPD Art. 18 VI; GDPR Art. 17; CCPA right to delete) | **Cryptographic erasure**: destroying a profile/volume key is verifiable, immediate deletion of everything under it; scoped deletion by re-keying; deletion events audited. | Whether/when erasure applies vs legal holds, labor-litigation retention, tax/books duties; what counts as anonymization vs pseudonymization. |
| **Correction** (LGPD Art. 18 III; GDPR Art. 16; CCPA correction) | Directory attributes and records are editable with full audited history of the change. | Verification standards and downstream-notification duties. |
| **Lawful-basis recording / purpose limitation** (LGPD Arts. 6–7; GDPR Arts. 5(1)(b), 6, 30) | Every policy object and every escrow release carries a **purpose string recorded verbatim** in the signed record; processing surfaces (telemetry items) are enumerated per policy version — a machine-readable input to the Art. 30 / registro de operações record. | Choosing the lawful basis per purpose (consent is usually inadequate in employment), writing the ROPA/registro, deciding when a DPIA/RIPD is required. |
| **Data minimization** (LGPD Art. 6 III; GDPR Art. 5(1)(c); CPRA minimization) | Default telemetry = inventory/posture/policy only; no content, no keystrokes; audit logs record events, not content; personal profile invisible to the org. Adding a telemetry item requires a new signed policy version — visible to employees. | Whether even the minimized set is proportionate for a given workforce/jurisdiction. |
| **Retention & secure deletion schedules** (LGPD Arts. 15–16; GDPR Art. 5(1)(e)) | Retention **labels** on volumes/records; expiry triggers cryptographic erasure jobs; deletion produces audit evidence. **Postern ships no default retention period on purpose.** | Every single retention period, and the disposition rule at expiry (delete/anonymize/archive). |
| **Audit logging / accountability** (LGPD Art. 6 X; GDPR Arts. 5(2), 24) | Hash-chained, dual-custody, signed audit log (§7); attested build (Postern Seal) proves the fleet runs the controls it claims. | What the accountability file must contain; how long to keep logs; DPO reporting lines. |
| **Breach detection & notification readiness** (LGPD Art. 48; GDPR Arts. 33–34; CCPA breach liability) | Attestation failures, wall violations, anomalous escrow activity, and revocation gaps raise alerts; the audit chain gives the forensic timeline; per-volume keys bound the blast radius of any single compromise; an **incident export** bundles the evidence a notification would need. | Whether an incident is a notifiable breach, the ANPD/DPA/AG timelines and content, affected-party communication — entirely counsel's call. |
| **Processor / DPA controls** (LGPD Arts. 39–40; GDPR Art. 28) | Self-hosted-first: directory, escrow, and audit run on org infrastructure by default, shrinking the processor list; where Postern Labs operates anything, the data flows are enumerated per policy version for the DPA annex. | Drafting/executing DPAs, sub-processor approval, international-transfer clauses. |
| **Cross-border transfers** (LGPD Arts. 33–36; GDPR Ch. V; CPRA contractual terms) | Region attributes on users/volumes let policy pin data and key material to jurisdiction-tagged infrastructure ("this volume's keys never leave BR/EU hosting"); egress classes make transfer paths explicit. | Whether a transfer mechanism (adequacy, SCCs, ANPD-approved clauses) exists and applies; Postern only makes the flows visible and controllable. |
| **Employee-monitoring transparency** (LGPD Arts. 9, 18; GDPR Arts. 12–14; local labor law) | The transparency panel (§8): itemized, signed, unremovable disclosure; no covert mode exists in the product. | Notice content, consultation duties (works councils, unions), and any monitoring lawfulness analysis. |
| **DPO / Encarregado function** (LGPD Art. 41; GDPR Arts. 37–39) | The **compliance-officer role** in the governance quorum gives the DPO real technical teeth: escrow approvals, audit-chain custody, policy countersignature. | Appointing a qualified DPO is mandatory in many contexts and is an organizational act, not a software feature. |

**What Postern deliberately does not provide:** legal templates presented as
sufficient, default retention periods, a "GDPR mode" switch, or any wording
that a purchase of Postern Enterprise makes an org compliant. It cannot.

## 10 · Reference console — `apps/postern-enterprise/index.html`

Codename **Consiglio** (cobalt accent; Sotto wears brass, Vedetta steel blue,
Tolmach verdigris, Chiave iris, Sarto madder, the Store amethyst). One
self-contained file, strict CSP from the first line; the **only possible**
network destination is the user's own optional Claude call for the policy
assistant (`api.anthropic.com`, exactly the Sotto/Sarto pattern) — everything
else is fully local. It demonstrates, with browser stand-ins labeled in-app:

- org bootstrap: admin-of-record + a **real 2-of-3 governance quorum** (each
  officer a WebCrypto keypair sealed under their own passphrase);
- the org tree, role catalog (RBAC), user attributes (ABAC), per-role machine
  profiles;
- the **Chinese-Wall editor**: COI classes → dataset groups → volumes, and a
  simulated file view where first access *binds* and conflicting volumes go
  cryptographically unavailable (key never released), with the advisory-limit
  disclosure on the panel itself;
- **provision** and **offboard** ceremonies, including a genuine
  **Shamir 2-of-3 escrow split/reconstruct** (GF(256)) gated on two officer
  passphrases, successor handover, key rotation, and wipe;
- the **hash-chained audit log** with a verify-the-chain button;
- the **employee transparency panel** — the exact screen a managed user sees;
- the NOT-LEGAL-ADVICE disclaimer, rendered permanently in the UI, and
  **LEGAL** flags on every counsel-owned decision the demo touches.

Stand-ins (labeled in the console's honesty dialog): Ed25519/P-256 WebCrypto
for Falcon‖ML-DSA; PBKDF2 for Argon2id; localStorage for the directory +
TEE + audit replica; in-page wall checks for the OS volume-key broker + MAC.
The flows are the design of record; the primitives are browser stand-ins.

## 11 · Honest limits — read before selling this

- **Compliance is not a product.** Repeated because it matters: this
  architecture *enables* a compliance program; a DPO + counsel *make* one.
- **Quorum-scale collusion reads corporate data.** That is escrow's stated
  purpose (business continuity, lawful access), not a backdoor — the control
  is auditability and notification, not impossibility. An org wanting
  employee data to be unrecoverable-even-by-the-org should not enroll it in
  escrow — and then owns the loss risk, like any seed holder.
- **The wall's hard edge is at-rest.** Key-withholding + OS MAC is strong;
  a cleared human with eyes and a phone camera is out of technical scope
  (§5.2). Do not let sales claim otherwise.
- **Availability trade:** short-lived assertions mean a dead directory
  degrades logins after the TTL. That is the price of instant revocation;
  offline-grace policy is the tunable, and it is visible to employees.
- **Insider-threat asymmetry:** the model constrains admins far more than
  most MDM (dual control, no content telemetry, tamper-evident audit), but a
  malicious org with physical fleet control is a threat model no endpoint
  software defeats. Postern's answer is transparency — the employee can at
  least *see* the powers claimed over the device.
- **Succession inherits entitlements, not judgment.** Wall bindings do not
  transfer; conflict checks re-run. But no system knows an org's real
  conflicts unless the COI classes are maintained — garbage walls in, garbage
  walls out.

---

> **⚠ Closing disclaimer — same as the opening one.** This document is
> engineering, not law. Postern Labs does not certify, warrant, or represent
> compliance with LGPD, GDPR, CCPA/CPRA, or any other regime. Every marker
> reading **LEGAL DETERMINATION REQUIRED (DPO/counsel)** is a decision this
> architecture is *waiting for* from qualified professionals — a DPO /
> Encarregado and admitted counsel in each jurisdiction — before an org
> relying on it can claim anything at all about compliance.
