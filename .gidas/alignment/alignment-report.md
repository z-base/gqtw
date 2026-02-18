# Alignment Report

## Status
- COMPLETED: spec indexes + cross-spec map generated from local working trees.

## What Changed
- Normalized GQTS requirement IDs in `openapi.yaml` from `REQ-R1..REQ-R7` to `REQ-GQTS-01..REQ-GQTS-07`.
- Added `localBiblio` entries in `index.html` for `GDIS-CORE`, `GQSCD-CORE`, and `GQTS-CORE`.
- Replaced local `web profile` and `EU compatibility profile` definitions in `index.html` with imported `data-cite` terms from `GQSCD-CORE`.
- Generated `spec-index.self.json`, `spec-index.peers.json`, and `cross-spec-map.json`.

## Duplicates Removed
- Removed duplicated local definition prose for:
  - `web profile`
  - `EU compatibility profile`

## Cross-References Added
- Added terminology imports:
  - `GQSCD-CORE#web-profile`
  - `GQSCD-CORE#eu-compatibility-profile`
- Added explicit bibliography entries for:
  - `GDIS-CORE`
  - `GQSCD-CORE`
  - `GQTS-CORE`

## Metrics
- term_clusters_with_multiple_members: 2
- term_definition_conflicts: 0
- requirement_namespace_conflicts: 0
- gaps_detected: 2

## Key Requirement Namespace Conflicts
- none

## Remaining Conflicts/Gaps
- Remaining gaps are placeholder requirement references that do not represent concrete anchors:
  - `GQSCD-CORE`: `REQ-GQSCD-`
  - `GQTS-CORE`: `REQ-GQTS-`
- See `cross-spec-map.json` (`conflicts[]`, `gaps[]`) for UNSPECIFIED/TODO items.
