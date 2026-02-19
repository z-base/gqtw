# Alignment Plan

## Canonical Term Owners
- proof artifact -> GQTW-CORE#proof-artifact
- binding credential -> UNSPECIFIED (term missing from current snapshots)
- gdis binding credential -> GDIS-CORE#gdis-binding-credential
- verification material -> GQTS-CORE#verification-material
- public verification material -> UNSPECIFIED (term missing from current snapshots)
- Device/key terms -> GQSCD-CORE (unless explicitly scoped as public verification material).
- Identity/PID terms -> GDIS-CORE.
- Log/publication terms -> GQTS-CORE.

## Canonical Clause Mapping
- getEndpointKindCatalog -> GQTS-CORE:REQ-GQTS-02
- getEventById -> GQTS-CORE:REQ-GQTS-07
- getEventHeadMeta -> GQTS-CORE:REQ-GQTS-04
- getEventLogView -> GQTS-CORE:REQ-GQTS-05
- getGdisPidIdentificationPolicy -> GDIS-CORE:REQ-GDIS-03
- getSchemeDescriptor -> GQTS-CORE:REQ-GQTS-01
- getTypeDescriptor -> GQTS-CORE:REQ-GQTS-03
- getWalletProfile -> GQTW-CORE:REQ-GQTW-13
- postErasureRequest -> GQTW-CORE:REQ-GQTW-11
- postEventIngest -> GQTS-CORE:REQ-GQTS-06
- postGqscdInvocation -> GQTW-CORE:REQ-GQTW-09
- postGqtsHeadHint -> GQTW-CORE:REQ-GQTW-08
- postPresentationRequest -> GQTW-CORE:REQ-GQTW-07
- postPresentationSubmission -> GQTW-CORE:REQ-GQTW-07
- postWalletExport -> GQTW-CORE:REQ-GQTW-10
- postWalletImport -> GQTW-CORE:REQ-GQTW-10
- postWalletIncidentReport -> GQTW-CORE:REQ-GQTW-08

## Clause Map (Refinement vs New)
- Refinement: REQ-GQTW-01 -> GQTS-CORE:REQ-GQTS-01..07, GQSCD-CORE:REQ-GQSCD-18,24, GDIS-CORE:REQ-GDIS-05
- Refinement: REQ-GQTW-02 -> GQSCD-CORE:REQ-GQSCD-18,26
- Refinement: REQ-GQTW-03 -> GQTS-CORE:REQ-GQTS-03,05,07
- New (wallet-private processing): REQ-GQTW-04
- Refinement: REQ-GQTW-05 -> GQTS-CORE:REQ-GQTS-04,05,07
- New (blind profile interface constraints): REQ-GQTW-06
- Refinement: REQ-GQTW-07 -> GQSCD-CORE:REQ-GQSCD-10,26, GDIS-CORE:REQ-GDIS-06
- Refinement: REQ-GQTW-08 -> GQTS-CORE:REQ-GQTS-04..07
- Refinement: REQ-GQTW-09 -> GQSCD-CORE:REQ-GQSCD-06,17,26..29
- New (wallet portability invariants): REQ-GQTW-10
- New (wallet privacy/erasure interface): REQ-GQTW-11
- Refinement: REQ-GQTW-12 -> GQSCD-CORE:REQ-GQSCD-08..10
- New (profile metadata output): REQ-GQTW-13
- New (conformance traceability outputs): REQ-GQTW-14
- New (GQES/GQEAA extension boundary): REQ-GQTW-15

## Required Changes In SELF (GQTW-CORE)
- No non-canonical local term definitions detected in SELF snapshot.
- Explicitly state that wallet proof artifacts/claims remain private and are not stored by trust services.
- Keep GDIS credential issuance semantics, but leave publication mechanics for private artifacts as UNSPECIFIED.
- Ensure any GQTS-hosted OpenAPI operations use canonical requirement IDs and schema-equivalent Proof/DID document structures.
- Ensure each requirement ID has a stable anchor or explicit alias anchor.

## No-Duplication Checklist
- [x] Canonical terms already owned by GDIS/GQTS/GQSCD are imported by reference in GQTW, not redefined.
- [x] GQTS endpoint semantics are referenced via GQTS operations/requirements instead of copied wire contracts.
- [x] GQSCD device and intent semantics are referenced via GQSCD requirements instead of cloned text.
- [x] New wallet-specific terms are scoped to GQTW-only deltas (private custody, portability, disclosure behavior).
- [x] New wallet-specific requirements use `REQ-GQTW-*` IDs with upstream clause dependencies cited.

## UNSPECIFIED
- OPRF/BBS profile details and blinded/unblinded flow details remain UNSPECIFIED unless separately profiled.
- Bad-node handling policy details beyond detect/flag/reject are UNSPECIFIED.
- Cross-repo peer edits are out of scope for this repo and remain UNSPECIFIED in this run.
