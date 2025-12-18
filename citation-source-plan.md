# Citation Network Index Builder - Implementation Plan

## Goal
Build a CLI tool that processes CommonCrawl's web graph to create a `tier1_citations` index mapping: `{target_domain: [list_of_tier1_domains_that_link_to_it]}`.

## Decisions
- **Memory**: 16+ GB available - use in-memory approach for speed
- **Index format**: JSON (simple, loads at API startup)
- **Automation**: Manual CLI only (no cron helpers)

## Memory & Size Estimates

### CommonCrawl Domain-Level Graph (Aug-Sep-Oct 2024)
| Asset | Compressed | Uncompressed (est.) |
|-------|------------|---------------------|
| Vertices | 679 MiB | ~2-3 GB |
| Edges | 6.8 GiB | ~30-50 GB |
| Total nodes | 96M domains | |
| Total edges | 1.7B links | |

### Our Output
- ~100 tier-1 source domains
- Each tier-1 domain links to ~10,000-100,000 unique domains
- Expected unique target domains with tier-1 citations: **1-5 million**
- Output index size: **50-200 MB** (JSON/SQLite)

### Peak Memory Usage (Streaming Approach)
| Component | Memory |
|-----------|--------|
| Tier-1 domain → node ID mapping | ~10 KB |
| All node ID → domain mapping (for lookups) | ~4-8 GB |
| Output accumulator | ~200-500 MB |
| **Total Peak** | **~5-9 GB RAM** |

### Selected Approach: In-Memory (16+ GB)
With 16+ GB RAM available, we'll use the faster in-memory approach:
- Load full vertex mapping into memory for O(1) lookups
- Single streaming pass through edges
- Estimated runtime: 10-30 minutes depending on I/O speed

## Folder Structure

```
citation-index/
├── README.md                 # Documentation
├── requirements.txt          # Dependencies (separate from main project)
├── cli.py                    # Main CLI entry point
├── config.py                 # Configuration (tier-1 domains, paths)
├── downloader.py             # Download CommonCrawl graph files
├── processor.py              # Core graph processing logic
├── index.py                  # Output index management (read/write)
└── output/
    └── tier1_citations.json  # Generated index (gitignored)
```

## CLI Interface

```bash
# Full pipeline (download + process + output)
python cli.py build --output ./output/tier1_citations.json

# Individual steps (for debugging/testing)
python cli.py download --dataset cc-main-2024-aug-sep-oct
python cli.py process --vertices ./cache/vertices.txt.gz --edges ./cache/edges.txt.gz
python cli.py stats --index ./output/tier1_citations.json

# Options
--cache-dir ./cache  # Where to store downloaded files (default: ./cache)
--dataset NAME       # CommonCrawl dataset name (default: latest)
--verbose            # Show progress details
```

## Processing Pipeline

### Step 1: Download
- Fetch domain-level vertices + edges from CommonCrawl S3
- URL pattern: `s3://commoncrawl/projects/hyperlinkgraph/cc-main-YYYY-xxx/domain/`
- Store in local cache directory

### Step 2: Build Node ID Mapping
- Stream vertices file (gzipped text: `<id>\t<rev_domain>\t<num_hosts>`)
- Build dict: `{node_id: domain}` for ALL nodes (needed for target lookup)
- Build set: `tier1_node_ids` for our ~100 tier-1 domains

### Step 3: Filter Edges
- Stream edges file (gzipped text: `<from_id>\t<to_id>`)
- For each edge where `from_id` in `tier1_node_ids`:
  - Resolve `to_id` to target domain
  - Add to output: `citations[target_domain].add(source_domain)`

### Step 4: Write Index
- Output format: JSON or SQLite
- Include metadata: source dataset, build date, tier-1 source count

## Output Format

```json
{
  "_metadata": {
    "version": "1.0.0",
    "source_dataset": "cc-main-2024-aug-sep-oct",
    "build_date": "2025-12-16",
    "tier1_source_count": 91,
    "indexed_domains": 2847391
  },
  "citations": {
    "example.com": ["nytimes.com", "bbc.com"],
    "another-site.org": ["nature.com", "wikipedia.org", "nih.gov"]
  }
}
```

## Integration with api.py

After building the index, add to `calculate_trust_score()`:

```python
# Load citation index at startup
citation_index = load_citation_index("citation-index/output/tier1_citations.json")

def calculate_trust_score(...):
    # ... existing logic ...

    # Citation bonus (new)
    citing_tier1 = citation_index.get(domain, [])
    if len(citing_tier1) >= 5:
        score += 20  # Strong citation signal
    elif len(citing_tier1) >= 2:
        score += 10  # Moderate citation signal
    elif len(citing_tier1) >= 1:
        score += 5   # Weak citation signal
```

## Dependencies (requirements.txt)

```
requests>=2.31.0      # HTTP downloads (fallback)
boto3>=1.34.0         # S3 access for CommonCrawl
click>=8.1.0          # CLI framework
tqdm>=4.66.0          # Progress bars
orjson>=3.9.0         # Fast JSON serialization
```

## Files to Create

| File | Purpose |
|------|---------|
| `citation-index/README.md` | Usage documentation |
| `citation-index/requirements.txt` | Isolated dependencies |
| `citation-index/cli.py` | Click-based CLI entry point |
| `citation-index/config.py` | Tier-1 domains list, CommonCrawl URLs |
| `citation-index/downloader.py` | S3/HTTP download with progress |
| `citation-index/processor.py` | Graph parsing and filtering |
| `citation-index/index.py` | JSON index read/write utilities |

## API Integration (after index is built)

Modify `/Users/drw/verque/search-engine/api.py`:
- Load citation index at startup (lazy load to avoid blocking)
- Add `cited_by_tier1` bonus in `calculate_trust_score()` (~line 1220)
