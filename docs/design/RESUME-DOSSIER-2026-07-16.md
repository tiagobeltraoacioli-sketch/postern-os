# Dossiê de retomada — Postern / Bloch
**PMO · consolidação de 8 relatórios de área · 2026-07-16**

> Gerado após queda de conexão, para retomar o desenvolvimento dos apps + updates do OS.
> Fonte: workflow `resume-state-analysis` (9 agentes Fable 5).

---

## Onde paramos — estado em-voo

**O que está decidido e fechado (design de registro).** As três edições de produto (Cloud, Container/Porog, Enterprise) têm design completo e internamente consistente, com um backlog PMO de execução (`designed-items-execution-backlog.md`) governado por quatro gates de honestidade inegociáveis: G1 built≠designed, G2 built≠booted≠hardware, G3 claims de atestação só com quote de hardware realmente lançado, G4 badge `unaudited` até auditoria terceirizada (nenhuma contratada para produtos; a do protocolo base está contratada mas **não feita**). O pivô OS Portal v2 ("Terem", nome pendente de trademark) está decidido em 8 docs (Cloud Hypervisor default, QEMU/Wine opt-in, bwrap obrigatório no App Mode). A decomposição Android está decidida (Porog=DPC managed-profile, NoporIS=control-plane dual-persona, Waydroid=escape hatch não-atestável), com contrato de consent-state compartilhado. O pipeline de CRL assinada (Bucket C) está **code-complete e verificado ao vivo** nos quatro hops. A frota Fly rodou o fix de finality/ASERT (v0.1.0-alpha3, commitado hoje de manhã).

**O que está realmente construído e testado (T0, host).** Somente: `postern-seal-companion` (verificador SEV-SNP real, 23 unit + 12 vector tests verdes contra fixture Milan — **só rejeições provadas; o caminho positivo nunca rodou em hardware**), os demais crates postern-*, `mobile/core` (Rust + UniFFI exportado), os gate kernels (gate-store verde), o código Terem no macOS (terem.rs 1005 linhas + terem-gate 2106 linhas, terem-gate 32/32 + terem.rs 16 testes, mas só sob TCG, nunca Linux/KVM), o Consiglio (console rico porém 100% localStorage — stand-ins clássicos, zero backend), e o pipeline CRL (bloqueado apenas por dois segredos de operador não setados). Evidências frescas de 2026-07-16: round-trip onion ao vivo do Courier e o marker-boot QEMU do Terem.

**O que foi cortado em pleno voo:**
1. **Build de imagens OS**: a decisão de abandonar o fluxo FOD-hash e usar o flake do próprio repo do protocolo está registrada (header SUPERSEDED em PACKAGE-FOD-HASHES.md) mas **não implementada no tree** — e 5 outros docs do bucketA ainda instruem o caminho morto. Nenhuma das 5 imagens jamais foi buildada; flake.lock é seed vazio; todos os blockers §0 do GO-LIVE abertos.
2. **Imagem mobile**: root cause achado e corrigido, build chegou a ~770/777 derivações e quebrou por qemu-user; o passo resumível está nomeado — **buildar nativo no Graviton aarch64** (que já existe).
3. **Frota Fly nós 7–10**: quatro configs untracked + edit não staged no fly.toml do primário (peer externo 45.32.154.137), no meio de um A/B de peering (IPv4 público vs 6PN privado por causa de hairpin NAT). **Um `git clean` perde tudo.**
4. **Android**: tudo Kotlin desenhado e scaffolded mas **nunca compilou** — não existe VM Linux+Nix, não há gradlew commitado, nenhum container Android jamais bootou. jniLibs/uniffi ainda são placeholders PLACE_*_HERE.
5. **Bucket C tail + Bucket F**: Dev C1 (redirect /gramota + publish-crl.sh) não entregue; os 5 devs F1–F5 são planejamento puro, zero código; bp-wt-site tem diff multi-bucket grande não commitado aguardando commit coordenado do PM.
6. **Docs defasados dos fatos**: os headers de os-portal-v2 ainda dizem "nada construído" (código existe); check-trust-labels.sh não cobre as superfícies NoporIS/Porog/Terem; POSTERN-APPS-ROADMAP atrasado (rename Vestnik, status Courier).

---

## Backlog de retomada

Ordem: desbloqueios de infra → app-dev → os-update → doc/legal. Deduplicado entre áreas.

| # | Item | Produto | Tipo | Esforço | Bloqueio |
|---|------|---------|------|---------|----------|
| 1 | Setar `LICENSE_ADMIN_TOKEN` (Pages) e `ADMIN_TOKEN` (Fly, **segredo distinto**) e publicar a 1ª CRL assinada (passos 3–5 do SIGNED-CRL-FLOW) | Licenciamento | infra | S | nenhum — só operador |
| 2 | Redeploy do primário Fly (peer externo 45.32.154.137) + deploy nós 7–10 (volumes gru, fase sync-only) | Bloch testnet | infra | S–M | nenhum |
| 3 | Decidir A/B de peering (node-7 IPv4 público vs 8–10 6PN), verificar convergência ao tip, flip `--mine` fase 2, e **commitar** os 4 configs + fly.toml | Bloch testnet | infra | S | item 2 observado |
| 4 | Arquivar pedido de quota EC2 (L-1216C47A → ≥96 vCPU, us-west-2) — assíncrono, arquivar já | Postern OS | infra | S | nenhum |
| 5 | Provisionar a VM Linux+Nix (JDK17, SDK 34, NDK r26, cargo-ndk, emulador, kernel binder+Waydroid, KVM, bwrap, runner CI) — **peça faltante de maior alavancagem** | transversal | infra | L | nenhum |
| 6 | Commitar gradlew wrappers + libs.versions.toml nos 4 projetos Android | Porog/NoporIS/wallet | infra | S | nenhum |
| 7 | Implementar o pivô de build no tree: apontar os/package.nix + seal-gate para o flake do repo do protocolo (supersessão FOD) e wire dos outputs `.#attested-image`/`.#cloud-image` | Postern OS / Cloud | infra | M | nenhum — decidido, não implementado |
| 8 | Congelar flake.lock (`scripts/flake-lock.sh`), pinar nixpkgs 24.05 + rev do mobile-nixos | Postern OS | infra | M | host Nix (item 5) |
| 9 | Preencher placeholders EC2 userdata (REPO_URL, AMI, IAM, EXPECT_COMMIT) | Postern OS | infra | S | remote git + LOCK_COMMIT |
| 10 | Superfície de honestidade CI: jobs t0:/t1:, `untested-inventory.yml`, estender `check-trust-labels.sh` p/ NoporIS/Porog/Terem + gate CI do android-bridge | transversal | infra | S | nenhum — roda no macOS hoje |
| 11 | Commit coordenado (PM) da working tree do bp-wt-site + triagem do `source.rs` untracked e push do commit pendente | site / l2-anchor | infra | M | re-rodar `git status` antes |
| 12 | Dev C1: redirect `/gramota → /apps/gramota/` em `_redirects` + `publish-crl.sh`; depois auditoria Advisor C1 | site / licenciamento | app-dev | S | nenhum |
| 13 | Ratificar o contrato gate-state compartilhado entre sloboda/noporis/porog/terem antes que os kernels bifurquem | kernel de consentimento | app-dev | S | nenhum |
| 14 | Bateria host-testável (macOS): reconcile-kernel Porog, consent_record.rs+audit.rs NoporIS, daemon sloboda-gated, Porog 02 Phase 0 | Porog/NoporIS/Waydroid | app-dev | M | nenhum |
| 15 | Bucket F (5 devs paralelos, host-testáveis): F1 daemon NoporIS, F2 persistência+E2E, F3 SDK Argon2id/XChaCha20, F4 colateral TCB Intel, F5 wasm+OCR+deploy | SDK/NoporIS/Seal | app-dev | M–L | registrar decisões F4 e F5b |
| 16 | E1 / Enterprise MVP-1: cerimônia real de device-key PQ (Falcon‖ML-DSA) substituindo stand-ins do Chiave/Consiglio | Enterprise | app-dev | L | nenhum |
| 17 | Enterprise MVP-2→4: Directory service real → volume-key broker OS-side → audit store dual-custody | Enterprise | app-dev | L | encadeado em 16 |
| 18 | Terem App Mode: `terem_app_run` + `resolve_bwrap_binary` (wrapper obrigatório) + schema app-mode | Terem | app-dev | M | ideal após item 27 |
| 19 | Primeiro build Gradle das árvores Android + cross-compile cargo-ndk + APK wallet — flipa G1 "built" | Porog/NoporIS/wallet | app-dev | M | itens 5+6 |
| 20 | Orquestrador on-device NoporIS (Substrate trait, 2 backends) + CrossProfileBrokerService — "headline gap" | NoporIS | app-dev | L | item 19 |
| 21 | Porog lifecycle T1 no emulador + K4 DPC managed-profile (peça definidora do Container, hoje zero código) | Porog/Container | app-dev | L | itens 5+19 |
| 22 | Provas T2 em hardware real: StrongBox/Key-Attestation, Play Integrity, matriz OEM — sempre manual/logado | Porog/Container | app-dev | L | Pixel StrongBox + phone aarch64 |
| 23 | Suite v0.1: bundles Tauri assinados (3 SOs); UI Vestnik sobre matrix-rust-sdk; polimento de panes | Suite/Vestnik | app-dev | M–L | nenhum |
| 24 | Bloch: k=8 como ramp progressivo com difficulty casada + finalizar TKV0 | Bloch-SIS-PoW | app-dev | L | nenhum (cautela: soft-fork revertida) |
| 25 | Verificador TDX real (DCAP/QVL) + CRL AMD KDS; adaptador vTPM Azure | Cloud | app-dev | L | hardware TDX |
| 26 | Build nativo da imagem mobile no **Graviton** (~7/777 derivações) + boot QEMU + publicar com label honesto | OS mobile | os-update | M | Graviton já existe |
| 27 | Verificação Linux do Terem: POC bwrap real, `terem_lifecycle` com KVM, `nix flake check` | Terem | os-update | S–M | box Linux c/ KVM (item 5) |
| 28 | Primeiro `nix build .#iso` real + staging S3 (blocker 0a — gatilho do GO-LIVE) | Postern OS | os-update | M | itens 7+8 |
| 29 | C1/C2: `.#attested-image` reproduzível 2× + cloud-image bootando em QEMU; inspecionar ESP | Cloud / OS | os-update | M | item 28 |
| 30 | GO-LIVE passos 1–5 do .#iso: dry-run, boot-verify em metal, repro 2 builders, publish R2, tripwires | Postern OS | os-update | L | 28 + quota + segredos operador |
| 31 | C3/C4: primeira VM SEV-SNP real (GCP) → primeiro verdict `Genuine` (satisfaz G3 — **flip de maior valor da tese**) | Cloud | os-update | L | 29 + conta GCP |
| 32 | Autorar `os/sloboda-compat.nix` (referenciado mas **inexistente**) + primeiro boot Waydroid vanilla | Waydroid | os-update | M | VM binder |
| 33 | stateVersion 25.05→24.05 em configuration/desktop/cloud.nix (fix pequeno e seguro) | Postern OS | os-update | S | nenhum |
| 34 | Boots de hardware dos ISOs Node/Desktop + device-boot dos apks pmOS | Postern OS | os-update | M | hardware físico |
| 35 | Reconciliar docs: bucketA c/ supersessão FOD (5 docs no caminho morto), headers stale do os-portal-v2, sync APPS-ROADMAP | docs | doc | S | confirmar item 7 |
| 36 | Registrar decisões abertas: F4 fallback-tier, F5b OCR, KYC_MODE, ConsentAuthority custody, USB, NAT default | docs | doc | S | founder |
| 37 | Legal: trademark Porog/NoporIS/Terem; sim de counsel p/ QEMU/Wine/bwrap; markers LEGAL do Enterprise | transversal | doc | M | counsel externo |
| 38 | Auditorias externas (cadeia SEV-SNP; design Enterprise) — hoje **nenhuma contratada** para produtos | Cloud + Enterprise | infra | L | MVPs existirem |

---

## Riscos & lacunas

**Inconsistências docs ↔ realidade:**
- bucketA contraditório: PACKAGE-FOD-HASHES declara FOD **SUPERSEDED**, mas IMAGE-TARGETS, FLAKE-PREFLIGHT, SEALGATE-FOD-PREFLIGHT, GO-LIVE e RUNBOOK ainda instruem o fluxo antigo — retomar pelo doc errado = caminho morto.
- os-portal-v2: headers dizem "nada construído", mas terem.rs/terem-gate/terem-compat.nix existem e estão commitados.
- READINESS.md (bucketA) pontuado antes da supersessão — otimista.
- POSTERN-APPS-ROADMAP defasado do POSTERN-ROADMAP.
- Graduação de fundação do backlog foi "por inspeção" — re-verificar que os testes dos crates passam.

**Riscos de honesty-gate (G1–G4):**
- **Nada é validado em hardware.** SEV-SNP só provou *rejeições*; nenhum verdict Genuine existe.
- **Nenhuma imagem OS jamais buildou/bootou** (5). Mobile nunca bootou. `.#attested-image` pode buildar verde e falhar no boot.
- **Kotlin/Android nunca compilou.** DPC/managed-profile (feature definidora do Container) tem zero código. Backend Enterprise inteiro é fake em localStorage.
- Tripwires CI defasados: check-trust-labels.sh não cobre noporis/porog/terem — overclaim passa no CI hoje.
- Root RKP do Google rotacionou 2026-02; verificador não faz CRL/revocação.

**Trabalho não durável (perda literal):**
- BlochSISPoW: 4 configs de nós + re-peering do primário só na working tree. bp-wt-site: diff grande não commitado. bloch-protocol: `source.rs` untracked + 1 commit não pushado.

**Rede/frota:**
- 6PN dos nós 8–10 é machine-specific — se o primário for recriado, os três ilham (usar `.internal`/--dns-seed). Peer externo 45.32.154.137 indocumentado.
- Chain roda k=4 forjável; soft-fork k=8 anterior **estagnou a chain e foi revertido**. Frota Postern-operada concentra hashrate (óptica 51%). Nunca rodou em WAN multi-nó.

**Decisões pendentes que bloqueiam execução:** F4 (fallback-tier), F5b (lib OCR), A/B de peering do node-7, Cloud Hypervisor vs QEMU p/ Windows gráfico, KYC_MODE, custódia da ConsentAuthority, recovery do canal TUF.

**Recursos externos ausentes:** segredos de operador (Pages/Fly, R2, minisign), conta GCP SEV-SNP, quota EC2, VM Linux+Nix, StrongBox, phone aarch64, hardware TDX, counsel.

---

## Primeiros 3 passos recomendados

1. **Setar os dois segredos (`LICENSE_ADMIN_TOKEN` no Pages + `ADMIN_TOKEN` no Fly) e publicar a primeira CRL assinada** — pipeline provado code-complete; único blocker é ~30 min de ação de operador.
2. **Fechar e commitar o loop da frota Fly** — redeploy do primário com o seed externo, deploy dos nós 7–10, resolver o A/B de peering e **commitar** os configs que hoje só existem na working tree (um checkout acidental apaga tudo).
3. **Provisionar a VM Linux+Nix (e arquivar o pedido de quota EC2 em paralelo)** — único desbloqueio que destrava simultaneamente o primeiro compile Android, o flake.lock, os builds de imagem OS, a verificação Linux do Terem e o caminho até o primeiro verdict SEV-SNP Genuine.
