Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Normalize-Text {
  param([string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
  $norm = $Text -replace '\s+', ' '
  return $norm.Trim().ToLowerInvariant()
}

function Normalize-Term {
  param([string]$Text)
  $norm = Normalize-Text $Text
  $norm = $norm -replace '[\p{P}]', ''
  $norm = $norm -replace '[_-]+', ' '
  if ($norm.EndsWith('s') -and $norm.Length -gt 3) {
    $norm = $norm.Substring(0, $norm.Length - 1)
  }
  return ($norm -replace '\s+', ' ').Trim()
}

function Strip-Html {
  param([string]$Html)
  if ([string]::IsNullOrEmpty($Html)) { return '' }
  $s = $Html -replace '<[^>]+>', ' '
  $s = $s -replace '&nbsp;', ' '
  $s = $s -replace '&amp;', '&'
  $s = $s -replace '&lt;', '<'
  $s = $s -replace '&gt;', '>'
  return ($s -replace '\s+', ' ').Trim()
}

function Get-Sha256 {
  param([string]$Text)
  $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $hash = $sha.ComputeHash($bytes)
    return ([System.BitConverter]::ToString($hash).Replace('-', '').ToLowerInvariant())
  } finally {
    $sha.Dispose()
  }
}

function New-Slug {
  param([string]$Text)
  $s = Normalize-Text $Text
  $s = $s -replace '[^a-z0-9\s-]', ''
  $s = $s -replace '\s+', '-'
  $s = $s -replace '-+', '-'
  return $s.Trim('-')
}

function Get-NormativeKeywords {
  param([string]$Text)
  $keywords = @('MUST', 'MUST NOT', 'SHOULD', 'SHOULD NOT', 'MAY', 'SHALL', 'SHALL NOT', 'REQUIRED', 'OPTIONAL')
  $found = New-Object System.Collections.Generic.List[string]
  foreach ($kw in $keywords) {
    if ($Text -match "(?<![A-Za-z])$([Regex]::Escape($kw))(?![A-Za-z])") {
      $found.Add($kw)
    }
  }
  return $found
}

function Find-SectionId {
  param(
    [System.Collections.Generic.List[object]]$SectionOffsets,
    [int]$Index
  )
  $result = $null
  foreach ($s in $SectionOffsets) {
    if ($s.position -le $Index) {
      $result = $s.id
    } else {
      break
    }
  }
  if ($null -eq $result) { return 'unspecified' }
  return $result
}

function Parse-ReSpecIndex {
  param(
    [string]$SpecId,
    [string]$Repo,
    [string]$HomeUrl,
    [string]$IndexPath,
    [string]$OpenApiPath
  )

  $html = Get-Content -Raw $IndexPath
  $sectionMatches = [regex]::Matches($html, '<section\s+id="([^"]+)"', 'IgnoreCase')
  $sectionOffsets = New-Object System.Collections.Generic.List[object]
  foreach ($m in $sectionMatches) {
    $sectionOffsets.Add([pscustomobject]@{
        id       = $m.Groups[1].Value
        position = $m.Index
      })
  }

  $terms = New-Object System.Collections.Generic.List[object]
  $dfnRx = '<dt>\s*<dfn(?<attrs>[^>]*)>(?<term>.*?)</dfn>.*?</dt>\s*<dd>(?<def>.*?)</dd>'
  $dfnMatches = [regex]::Matches($html, $dfnRx, 'IgnoreCase,Singleline')
  foreach ($m in $dfnMatches) {
    $attrs = $m.Groups['attrs'].Value
    $termRaw = Strip-Html $m.Groups['term'].Value
    $defRaw = Strip-Html $m.Groups['def'].Value
    $importedFrom = $null
    if ($attrs -match 'data-cite="([^"]+)"') {
      $importedFrom = $Matches[1]
    }
    $anchor = ''
    if ($attrs -match 'id="([^"]+)"') {
      $anchor = $Matches[1]
    } elseif (-not [string]::IsNullOrWhiteSpace($importedFrom) -and $importedFrom -match '#(.+)$') {
      $anchor = $Matches[1]
    } elseif ($attrs -match 'data-lt="([^"]+)"') {
      $anchor = New-Slug (($Matches[1] -split '\|')[0])
    } else {
      $anchor = New-Slug $termRaw
    }
    $defNorm = Normalize-Text $defRaw
    $sectionId = Find-SectionId -SectionOffsets $sectionOffsets -Index $m.Index
    $terms.Add([pscustomobject]@{
        term_text                = $termRaw
        normalized_term          = Normalize-Term $termRaw
        term_id                  = $anchor
        anchor                   = "#$anchor"
        section_anchor           = "#$sectionId"
        definition_excerpt_hash  = Get-Sha256 $defNorm
        definition_text_excerpt  = if ($defRaw.Length -gt 240) { $defRaw.Substring(0, 240) } else { $defRaw }
        imported_from            = $importedFrom
      })
  }

  # Capture standalone <dfn> terms that are not expressed as <dt>/<dd> pairs
  # (for example, Annex clause labels in tables).
  $existingTermKeys = @{}
  foreach ($t in $terms) {
    $existingTermKeys["$($t.anchor)|$($t.normalized_term)"] = $true
  }
  $allDfnMatches = [regex]::Matches($html, '<dfn(?<attrs>[^>]*)>(?<term>.*?)</dfn>', 'IgnoreCase,Singleline')
  foreach ($m in $allDfnMatches) {
    $attrs = $m.Groups['attrs'].Value
    $termRaw = Strip-Html $m.Groups['term'].Value
    $importedFrom = $null
    if ($attrs -match 'data-cite="([^"]+)"') {
      $importedFrom = $Matches[1]
    }

    $anchor = ''
    if ($attrs -match 'id="([^"]+)"') {
      $anchor = $Matches[1]
    } elseif (-not [string]::IsNullOrWhiteSpace($importedFrom) -and $importedFrom -match '#(.+)$') {
      $anchor = $Matches[1]
    } elseif ($attrs -match 'data-lt="([^"]+)"') {
      $anchor = New-Slug (($Matches[1] -split '\|')[0])
    } else {
      $anchor = New-Slug $termRaw
    }

    $normalized = Normalize-Term $termRaw
    $termKey = "#$anchor|$normalized"
    if ($existingTermKeys.ContainsKey($termKey)) {
      continue
    }
    $existingTermKeys[$termKey] = $true

    $sectionId = Find-SectionId -SectionOffsets $sectionOffsets -Index $m.Index
    $terms.Add([pscustomobject]@{
        term_text                = $termRaw
        normalized_term          = $normalized
        term_id                  = $anchor
        anchor                   = "#$anchor"
        section_anchor           = "#$sectionId"
        definition_excerpt_hash  = Get-Sha256 ''
        definition_text_excerpt  = ''
        imported_from            = $importedFrom
      })
  }

  $clauses = New-Object System.Collections.Generic.List[object]
  $clauseRx = 'id="(?<anchor>(?:REQ-[A-Z0-9-]+|req-[a-z0-9-]+))"'
  $clauseMatches = [regex]::Matches($html, $clauseRx)
  foreach ($m in $clauseMatches) {
    $anchor = $m.Groups['anchor'].Value
    $excerptStart = [Math]::Max(0, $m.Index - 40)
    $excerptLen = [Math]::Min(400, $html.Length - $excerptStart)
    $excerpt = Strip-Html $html.Substring($excerptStart, $excerptLen)
    $clauseId = $anchor
    if ($anchor -match '^req-') {
      $reqMatch = [regex]::Match($excerpt, 'REQ-[A-Z0-9-]+')
      if ($reqMatch.Success) {
        $clauseId = $reqMatch.Value
      }
    }
    $clauses.Add([pscustomobject]@{
        clause_id               = $clauseId
        anchor                  = "#$anchor"
        kind                    = 'requirement'
        normative_keywords_used = @(Get-NormativeKeywords $excerpt)
        text_excerpt_hash       = Get-Sha256 (Normalize-Text $excerpt)
      })
  }

  $refs = New-Object System.Collections.Generic.List[object]
  $hrefMatches = [regex]::Matches($html, 'href="https://z-base.github.io/(gdis|gqscd|gqts)/?"')
  foreach ($m in $hrefMatches) {
    $refs.Add([pscustomobject]@{
        type  = 'href'
        value = ($m.Value -replace '^href="|"$', '')
      })
  }
  $labelMatches = [regex]::Matches($html, '\[(GDIS-CORE|GQSCD-CORE|GQTS-CORE)\]')
  foreach ($m in $labelMatches) {
    $refs.Add([pscustomobject]@{
        type  = 'label'
        value = $m.Groups[1].Value
      })
  }

  $openapi = $null
  if ($OpenApiPath -and (Test-Path $OpenApiPath)) {
    $openapiText = Get-Content -Raw $OpenApiPath
    $lines = Get-Content $OpenApiPath

    $operations = New-Object System.Collections.Generic.List[object]
    $schemas = New-Object System.Collections.Generic.List[object]
    $requirementMaps = New-Object System.Collections.Generic.List[object]

    $currentReqMap = $null
    foreach ($line in $lines) {
      if ($line -match '^(x-[a-z0-9-]+requirements):\s*$') {
        $currentReqMap = $Matches[1]
        continue
      }
      if ($null -ne $currentReqMap -and $line -match '^\s{2}([A-Z0-9-]+):\s*(.+)$') {
        $requirementMaps.Add([pscustomobject]@{
            map_key        = $currentReqMap
            requirement_id = $Matches[1]
            description     = $Matches[2]
          })
        continue
      }
      if ($null -ne $currentReqMap -and $line -notmatch '^\s{2}') {
        $currentReqMap = $null
      }
    }

    $currentPath = $null
    $currentMethod = $null
    $operation = $null
    $inOperation = $false

    function Commit-Operation {
      param([object]$Op, [System.Collections.Generic.List[object]]$Ops)
      if ($null -ne $Op -and -not [string]::IsNullOrWhiteSpace($Op.operationId)) {
        $hashInput = "{0}|{1}|{2}|{3}|{4}" -f $Op.method, $Op.path, $Op.operationId, (($Op.media_types | Sort-Object) -join ','), (($Op.schema_refs | Sort-Object) -join ',')
        $Op | Add-Member -NotePropertyName operation_contract_hash -NotePropertyValue (Get-Sha256 (Normalize-Text $hashInput))
        $Ops.Add($Op)
      }
    }

    foreach ($line in $lines) {
      if ($line -match '^  (/[^:]+):\s*$') {
        Commit-Operation -Op $operation -Ops $operations
        $operation = $null
        $currentPath = $Matches[1]
        $currentMethod = $null
        $inOperation = $false
        continue
      }

      if ($line -match '^\s{4}(get|post|put|delete|patch|head|options|trace):\s*$') {
        Commit-Operation -Op $operation -Ops $operations
        $currentMethod = $Matches[1]
        $operation = [pscustomobject]@{
          operationId = ''
          method = $currentMethod
          path = $currentPath
          requirement_key = $null
          x_requirement = $null
          media_types = New-Object System.Collections.Generic.List[string]
          schema_refs = New-Object System.Collections.Generic.List[string]
        }
        $inOperation = $true
        continue
      }

      if (-not $inOperation -or $null -eq $operation) {
        continue
      }

      if ($line -match '^\s{6}operationId:\s*(.+)$') {
        $operation.operationId = $Matches[1].Trim()
        continue
      }
      if ($line -match '^\s{6}(x-[a-z0-9-]+requirement):\s*(.+)$') {
        $operation.requirement_key = $Matches[1]
        $operation.x_requirement = $Matches[2].Trim()
        continue
      }
      if ($line -match '^\s{12}([A-Za-z0-9.+-]+/[A-Za-z0-9.+-]+):\s*$') {
        $operation.media_types.Add($Matches[1])
        continue
      }
      if ($line -match "#/components/schemas/([A-Za-z0-9_.-]+)") {
        $operation.schema_refs.Add($Matches[1])
        continue
      }
    }
    Commit-Operation -Op $operation -Ops $operations

    $schemaSectionMatch = [regex]::Match($openapiText, '(?ms)^  schemas:\s*(?<body>.*)$')
    if ($schemaSectionMatch.Success) {
      $schemaBody = $schemaSectionMatch.Groups['body'].Value
      $schemaStartMatches = [regex]::Matches($schemaBody, '(?m)^    ([A-Za-z0-9_.-]+):\s*$')
      for ($i = 0; $i -lt $schemaStartMatches.Count; $i++) {
        $name = $schemaStartMatches[$i].Groups[1].Value
        $start = $schemaStartMatches[$i].Index
        $end = if ($i + 1 -lt $schemaStartMatches.Count) { $schemaStartMatches[$i + 1].Index } else { $schemaBody.Length }
        $block = $schemaBody.Substring($start, $end - $start)
        $schemas.Add([pscustomobject]@{
            name = $name
            json_pointer = "/components/schemas/$name"
            key_constraints_hash = Get-Sha256 (Normalize-Text (Strip-Html $block))
          })
      }
    }

    $openapi = [pscustomobject]@{
      operations = $operations
      schemas = $schemas
      requirement_maps = $requirementMaps
    }
  }

  return [pscustomobject]@{
    spec_id = $SpecId
    repo = $Repo
    commit_or_version = 'unspecified'
    home_url = $HomeUrl
    files = [pscustomobject]@{
      index_html = $IndexPath
      openapi_yaml = if ($OpenApiPath -and (Test-Path $OpenApiPath)) { $OpenApiPath } else { $null }
      agents_md = 'AGENTS.md'
    }
    terms = $terms
    clauses = $clauses
    cross_spec_references = $refs
    openapi = $openapi
  }
}

function Resolve-TermOwner {
  param([string]$NormalizedTerm, [object[]]$Members)

  $explicitOwners = @{
    'web profile' = 'GQSCD-CORE'
    'eu compatibility profile' = 'GQSCD-CORE'
  }
  if ($explicitOwners.ContainsKey($NormalizedTerm)) {
    return $explicitOwners[$NormalizedTerm]
  }

  $deviceHints = @('device', 'controller', 'sole control', 'intent', 'qscd', 'tee', 'attestation')
  $identityHints = @('pid', 'mrz', 'identity', 'binding', 'gdis')
  $gqtsHints = @('event', 'log', 'host', 'scheme descriptor', 'service descriptor', 'replication', 'gqts', 'head digest')

  foreach ($h in $deviceHints) {
    if ($NormalizedTerm -like "*$h*") { return 'GQSCD-CORE' }
  }
  foreach ($h in $identityHints) {
    if ($NormalizedTerm -like "*$h*") { return 'GDIS-CORE' }
  }
  foreach ($h in $gqtsHints) {
    if ($NormalizedTerm -like "*$h*") { return 'GQTS-CORE' }
  }

  # Cross-cutting fallback: pick the spec where the term was first declared.
  return $Members[0].spec_id
}

function Resolve-ClauseOwner {
  param([string]$OperationId)
  if ($OperationId -like 'getGdis*') { return 'GDIS-CORE' }
  return 'GQTS-CORE'
}

$selfRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$outDir = Join-Path $selfRoot '.gidas\alignment'
if (-not (Test-Path $outDir)) {
  New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$selfIndex = Parse-ReSpecIndex `
  -SpecId 'GDIS-CORE' `
  -Repo 'z-base/gdis' `
  -HomeUrl 'https://z-base.github.io/gdis/' `
  -IndexPath (Join-Path $selfRoot 'index.html') `
  -OpenApiPath (Join-Path $selfRoot 'openapi.yaml')

$peerSpecs = @(
  @{ spec_id = 'GQSCD-CORE'; repo = 'z-base/gqscd'; home_url = 'https://z-base.github.io/gqscd/'; index = '..\gqscd\index.html'; openapi = $null },
  @{ spec_id = 'GQTS-CORE'; repo = 'z-base/gqts'; home_url = 'https://z-base.github.io/gqts/'; index = '..\gqts\index.html'; openapi = '..\gqts\openapi.yaml' }
)

$peers = New-Object System.Collections.Generic.List[object]
$missingPeers = New-Object System.Collections.Generic.List[string]
foreach ($peer in $peerSpecs) {
  $peerIndexPath = Resolve-Path (Join-Path $selfRoot $peer.index) -ErrorAction SilentlyContinue
  if ($null -eq $peerIndexPath) {
    $missingPeers.Add($peer.spec_id)
    continue
  }
  $peerOpenApi = $null
  if ($peer.openapi) {
    $resolved = Resolve-Path (Join-Path $selfRoot $peer.openapi) -ErrorAction SilentlyContinue
    if ($null -ne $resolved) {
      $peerOpenApi = $resolved.Path
    }
  }
  $peers.Add(
    (Parse-ReSpecIndex `
      -SpecId $peer.spec_id `
      -Repo $peer.repo `
      -HomeUrl $peer.home_url `
      -IndexPath $peerIndexPath.Path `
      -OpenApiPath $peerOpenApi)
  )
}

$specIndexSelfPath = Join-Path $outDir 'spec-index.self.json'
$specIndexPeersPath = Join-Path $outDir 'spec-index.peers.json'
$crossMapPath = Join-Path $outDir 'cross-spec-map.json'
$reportPath = Join-Path $outDir 'alignment-report.md'

$selfIndex | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 $specIndexSelfPath
$peers | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 $specIndexPeersPath

if ($missingPeers.Count -gt 0) {
  @(
    '# Alignment Report'
    ''
    '## Status'
    '- FAILED_CLOSED: missing peer snapshots'
    ''
    '## Missing peers'
    ($missingPeers | ForEach-Object { "- $_" })
    ''
    'Provide local peer snapshots and rerun `.gidas/alignment/generate-alignment.ps1`.'
  ) | Set-Content -Encoding UTF8 $reportPath
  throw "Missing peer snapshots: $($missingPeers -join ', ')"
}

$allSpecs = @($selfIndex) + @($peers.ToArray())
$termGroups = @{}
foreach ($spec in $allSpecs) {
  foreach ($term in $spec.terms) {
    if (-not $termGroups.ContainsKey($term.normalized_term)) {
      $termGroups[$term.normalized_term] = New-Object System.Collections.Generic.List[object]
    }
    $termGroups[$term.normalized_term].Add([pscustomobject]@{
        spec_id = $spec.spec_id
        term_text = $term.term_text
        anchor = $term.anchor
        definition_excerpt_hash = $term.definition_excerpt_hash
        imported_from = $term.imported_from
      })
  }
}

$canonicalTerms = New-Object System.Collections.Generic.List[object]
$conflicts = New-Object System.Collections.Generic.List[object]
foreach ($key in ($termGroups.Keys | Sort-Object)) {
  $members = $termGroups[$key]
  $owner = Resolve-TermOwner -NormalizedTerm $key -Members $members
  $ownerMember = $members | Where-Object { $_.spec_id -eq $owner } | Select-Object -First 1
  if ($null -eq $ownerMember) {
    $ownerMember = $members[0]
    $owner = $ownerMember.spec_id
  }

  $localMembers = @($members | Where-Object { [string]::IsNullOrWhiteSpace($_.imported_from) })
  $hashes = @($localMembers | Select-Object -ExpandProperty definition_excerpt_hash -Unique)
  if ($localMembers.Count -gt 1 -and $hashes.Count -gt 1) {
    $conflicts.Add([pscustomobject]@{
        type = 'term-definition-conflict'
        concept = $key
        members = $members
      })
  }

  $canonicalTerms.Add([pscustomobject]@{
      canonical_term = $key
      canonical_owner_spec_id = $owner
      canonical_anchor = $ownerMember.anchor
      aliases = @($members | Select-Object -ExpandProperty term_text -Unique)
      members = $members
    })
}

$operationRows = New-Object System.Collections.Generic.List[object]
foreach ($spec in $allSpecs) {
  if ($null -eq $spec.openapi) { continue }
  foreach ($op in $spec.openapi.operations) {
    $operationRows.Add([pscustomobject]@{
        spec_id = $spec.spec_id
        operationId = $op.operationId
        method = $op.method
        path = $op.path
        requirement_id = $op.x_requirement
        requirement_key = $op.requirement_key
      })
  }
}

$operationGroups = @{}
foreach ($row in $operationRows) {
  if ([string]::IsNullOrWhiteSpace($row.operationId)) { continue }
  if (-not $operationGroups.ContainsKey($row.operationId)) {
    $operationGroups[$row.operationId] = New-Object System.Collections.Generic.List[object]
  }
  $operationGroups[$row.operationId].Add($row)
}

$canonicalClauses = New-Object System.Collections.Generic.List[object]
foreach ($opId in ($operationGroups.Keys | Sort-Object)) {
  $members = $operationGroups[$opId]
  $owner = Resolve-ClauseOwner -OperationId $opId
  $ownerMember = $members | Where-Object { $_.spec_id -eq $owner } | Select-Object -First 1
  if ($null -eq $ownerMember) {
    $ownerMember = $members[0]
    $owner = $ownerMember.spec_id
  }
  $canonicalClauses.Add([pscustomobject]@{
      clause_concept = $opId
      canonical_owner_spec_id = $owner
      canonical_clause_id = $ownerMember.requirement_id
      member_clause_ids = @($members | ForEach-Object { "$($_.spec_id):$($_.requirement_id)" })
    })

  $reqIds = @($members | Select-Object -ExpandProperty requirement_id -Unique)
  if ($reqIds.Count -gt 1) {
    $conflicts.Add([pscustomobject]@{
        type = 'requirement-namespace-conflict'
        concept = $opId
        members = $members
      })
  }
}

$allDefinedTerms = @{}
foreach ($spec in $allSpecs) {
  foreach ($term in $spec.terms) {
    $allDefinedTerms[$term.normalized_term] = $true
  }
}

$gaps = New-Object System.Collections.Generic.List[object]
foreach ($spec in $allSpecs) {
  $content = Get-Content -Raw $spec.files.index_html
  $termRefs = [regex]::Matches($content, '\[=([^=\]]+)=\]')
  foreach ($ref in $termRefs) {
    $t = Normalize-Term $ref.Groups[1].Value
    if (-not $allDefinedTerms.ContainsKey($t)) {
      $gaps.Add([pscustomobject]@{
          type = 'undefined-term-reference'
          spec_id = $spec.spec_id
          reference = $ref.Groups[1].Value
        })
    }
  }

  $reqRefs = [regex]::Matches($content, 'REQ-[A-Z0-9-]+')
  $clauseSet = @{}
  foreach ($c in $spec.clauses) {
    $clauseSet[$c.clause_id] = $true
  }
  foreach ($rr in $reqRefs) {
    $req = $rr.Value
    if (-not $clauseSet.ContainsKey($req)) {
      $gaps.Add([pscustomobject]@{
          type = 'missing-requirement-anchor'
          spec_id = $spec.spec_id
          reference = $req
        })
    }
  }
}

$crossMap = [pscustomobject]@{
  canonical_terms = $canonicalTerms
  canonical_clauses = $canonicalClauses
  conflicts = $conflicts
  gaps = $gaps
}
$crossMap | ConvertTo-Json -Depth 12 | Set-Content -Encoding UTF8 $crossMapPath

$dupCount = 0
foreach ($ct in $canonicalTerms) {
  $memberCount = ($ct.members | Measure-Object).Count
  if ($memberCount -gt 1) {
    $dupCount++
  }
}
$termConflictCount = ($conflicts | Where-Object { $_.type -eq 'term-definition-conflict' } | Measure-Object).Count
$reqConflictCount = ($conflicts | Where-Object { $_.type -eq 'requirement-namespace-conflict' } | Measure-Object).Count
$gapCount = ($gaps | Measure-Object).Count

$topReqConflicts = $conflicts |
  Where-Object { $_.type -eq 'requirement-namespace-conflict' } |
  Select-Object -First 12

$reportLines = New-Object System.Collections.Generic.List[string]
$reportLines.Add('# Alignment Report')
$reportLines.Add('')
$reportLines.Add('## Status')
$reportLines.Add('- COMPLETED: spec indexes + cross-spec map generated from local working trees.')
$reportLines.Add('')
$reportLines.Add('## What Changed')
$reportLines.Add('- Generated `spec-index.self.json` for `GDIS-CORE`.')
$reportLines.Add('- Generated `spec-index.peers.json` for `GQSCD-CORE` and `GQTS-CORE` from local sibling repos.')
$reportLines.Add('- Generated `cross-spec-map.json` with canonical term/clause ownership, conflicts, and gaps.')
$reportLines.Add('')
$reportLines.Add('## Duplicates Removed')
$reportLines.Add('- NONE in this generation-only step (spec edits are applied separately).')
$reportLines.Add('')
$reportLines.Add('## Cross-References Added')
$reportLines.Add('- NONE in this generation-only step (spec edits are applied separately).')
$reportLines.Add('')
$reportLines.Add('## Metrics')
$reportLines.Add("- term_clusters_with_multiple_members: $dupCount")
$reportLines.Add("- term_definition_conflicts: $termConflictCount")
$reportLines.Add("- requirement_namespace_conflicts: $reqConflictCount")
$reportLines.Add("- gaps_detected: $gapCount")
$reportLines.Add('')
$reportLines.Add('## Key Requirement Namespace Conflicts')
if ((($topReqConflicts | Measure-Object).Count) -eq 0) {
  $reportLines.Add('- none')
} else {
  foreach ($c in $topReqConflicts) {
    $members = ($c.members | ForEach-Object { "$($_.spec_id) $($_.method.ToUpper()) $($_.path) -> $($_.requirement_id)" }) -join '; '
    $reportLines.Add("- $($c.concept): $members")
  }
}
$reportLines.Add('')
$reportLines.Add('## Remaining Conflicts/Gaps')
$reportLines.Add('- See `cross-spec-map.json` (`conflicts[]`, `gaps[]`) for UNSPECIFIED/TODO items requiring editorial decisions.')

$reportLines | Set-Content -Encoding UTF8 $reportPath
