# Citation Graph Analysis for Academic Content

## Overview

Add citation graph analysis to distinguish important research from fake/low-quality research using:
1. **Serper Scholar API** (`/scholar`) - New search mode for academic queries
2. **Semantic Scholar API** (free) - Enrich academic URLs with citation authority data

## Requirements Summary

- **Integration**: Extend `trust_score` + add new `academic_authority` field
- **Signals**: Citation count weighted by recency
- **Preprints**: Flag with warning but don't penalize score

---

## Implementation Plan

### Phase 1: Data Models & Detection

**File**: `api.py`

#### 1.1 Add Academic Detection Patterns

```python
ACADEMIC_URL_PATTERNS = [
    r'arxiv\.org',
    r'doi\.org/10\.',
    r'pubmed\.ncbi\.nlm\.nih\.gov',
    r'ncbi\.nlm\.nih\.gov/pmc',
    r'scholar\.google\.com',
    r'semanticscholar\.org',
    r'ieee\.org',
    r'acm\.org/doi',
    r'sciencedirect\.com',
    r'springer\.com',
    r'nature\.com/articles',
    r'science\.org/doi',
    r'biorxiv\.org',
    r'medrxiv\.org',
    r'ssrn\.com',
    r'researchgate\.net/publication',
]

PREPRINT_PATTERNS = [
    r'arxiv\.org',
    r'biorxiv\.org',
    r'medrxiv\.org',
    r'ssrn\.com',
]
```

#### 1.2 New Data Models

```python
class AcademicMetadata(BaseModel):
    paper_id: Optional[str] = None           # Semantic Scholar paper ID
    doi: Optional[str] = None
    title: Optional[str] = None
    citation_count: int = 0
    influential_citation_count: int = 0       # Citations from influential papers
    citation_velocity: float = 0.0            # Recent citations per year
    year: Optional[int] = None
    venue: Optional[str] = None               # Journal/conference name
    is_preprint: bool = False
    is_open_access: bool = False
    authors: List[str] = []
    fields_of_study: List[str] = []

class AcademicAuthority(BaseModel):
    score: float = 0.0                        # 0-100 academic authority score
    citation_score: float = 0.0               # Raw citation-based score
    recency_weight: float = 1.0               # Multiplier for recent citations
    metadata: Optional[AcademicMetadata] = None
    warnings: List[str] = []                  # "preprint", "low_citations", etc.
```

#### 1.3 Extend Existing Models

```python
# Add to VerqueMetadata
class VerqueMetadata(BaseModel):
    tier: int = 2
    trust_score: int = 50
    classification: Optional[Classification] = None
    warnings: List[str] = []
    academic_authority: Optional[AcademicAuthority] = None  # NEW
    is_academic: bool = False                                # NEW

# Add to SearchRequest
class SearchRequest(BaseModel):
    query: str
    num_results: int = 10
    ai_classification: bool = True
    verify_claims: bool = False
    search_type: str = "web"  # NEW: "web" | "scholar"
```

---

### Phase 2: Semantic Scholar Integration

**File**: `api.py`

#### 2.1 Semantic Scholar API Client

```python
SEMANTIC_SCHOLAR_API = "https://api.semanticscholar.org/graph/v1"

async def get_semantic_scholar_paper(identifier: str) -> Optional[AcademicMetadata]:
    """
    Lookup paper by DOI, arXiv ID, or URL.
    Free tier: 100 requests/second
    """
    # Extract identifier from URL if needed
    paper_id = extract_paper_identifier(identifier)
    if not paper_id:
        return None

    url = f"{SEMANTIC_SCHOLAR_API}/paper/{paper_id}"
    params = {
        "fields": "paperId,title,year,venue,citationCount,influentialCitationCount,"
                  "isOpenAccess,authors,fieldsOfStudy,citations.year"
    }

    async with httpx.AsyncClient() as client:
        response = await client.get(url, params=params, timeout=5.0)
        if response.status_code == 200:
            data = response.json()
            return parse_semantic_scholar_response(data)
    return None

def extract_paper_identifier(url: str) -> Optional[str]:
    """Extract DOI or arXiv ID from URL for Semantic Scholar lookup."""
    # DOI pattern: doi.org/10.xxxx/yyyy or embedded DOI
    doi_match = re.search(r'(10\.\d{4,}/[^\s]+)', url)
    if doi_match:
        return f"DOI:{doi_match.group(1)}"

    # arXiv pattern: arxiv.org/abs/xxxx.xxxxx
    arxiv_match = re.search(r'arxiv\.org/(?:abs|pdf)/(\d+\.\d+)', url)
    if arxiv_match:
        return f"arXiv:{arxiv_match.group(1)}"

    # PMID pattern
    pmid_match = re.search(r'pubmed\.ncbi\.nlm\.nih\.gov/(\d+)', url)
    if pmid_match:
        return f"PMID:{pmid_match.group(1)}"

    return None
```

#### 2.2 Calculate Recency-Weighted Citation Score

```python
def calculate_academic_authority(metadata: AcademicMetadata) -> AcademicAuthority:
    """
    Calculate academic authority score from citation data.
    Recent citations weighted higher than old ones.
    """
    warnings = []

    # Base citation score (log scale to handle papers with 1000s of citations)
    if metadata.citation_count > 0:
        citation_score = min(100, 20 * math.log10(metadata.citation_count + 1))
    else:
        citation_score = 0
        warnings.append("no_citations")

    # Recency weight: papers cited recently get a boost
    current_year = datetime.now().year
    if metadata.year:
        paper_age = current_year - metadata.year
        if paper_age <= 2:
            recency_weight = 1.2  # New papers get slight boost
        elif paper_age <= 5:
            recency_weight = 1.0
        else:
            # Older papers need more citations to maintain relevance
            recency_weight = 0.9
    else:
        recency_weight = 1.0

    # Influential citations bonus (citations from important papers)
    if metadata.influential_citation_count > 10:
        citation_score += 15
    elif metadata.influential_citation_count > 5:
        citation_score += 10

    # Preprint warning (no penalty)
    if metadata.is_preprint:
        warnings.append("preprint")

    # Low citation warning for older papers
    if metadata.year and (current_year - metadata.year) > 3 and metadata.citation_count < 5:
        warnings.append("low_citations")

    final_score = min(100, citation_score * recency_weight)

    return AcademicAuthority(
        score=final_score,
        citation_score=citation_score,
        recency_weight=recency_weight,
        metadata=metadata,
        warnings=warnings
    )
```

#### 2.3 Caching Strategy

```python
# Add to RedisCache class
ACADEMIC_CACHE_TTL = 86400 * 3  # 3 days (citation counts don't change fast)

async def get_cached_academic_data(self, identifier: str) -> Optional[dict]:
    key = f"academic:{identifier}"
    return await self.get(key)

async def set_cached_academic_data(self, identifier: str, data: dict):
    key = f"academic:{identifier}"
    await self.set(key, data, ttl=ACADEMIC_CACHE_TTL)
```

---

### Phase 3: Serper Scholar Integration

**File**: `api.py`

#### 3.1 Add Scholar Search Function

```python
async def search_serper_scholar(query: str, num_results: int = 10) -> List[dict]:
    """
    Search Google Scholar via Serper API.
    Returns academic papers with citation counts.
    """
    url = "https://google.serper.dev/scholar"
    headers = {
        "X-API-KEY": SERPER_API_KEY,
        "Content-Type": "application/json"
    }
    payload = {
        "q": query,
        "num": num_results
    }

    async with httpx.AsyncClient() as client:
        response = await client.post(url, headers=headers, json=payload, timeout=10.0)
        response.raise_for_status()
        data = response.json()
        return data.get("organic", [])
```

#### 3.2 Modify Search Endpoint

```python
@app.post("/search", response_model=SearchResponse)
async def search(request: SearchRequest, ...):
    # Choose search backend based on search_type
    if request.search_type == "scholar":
        raw_results = await search_serper_scholar(request.query, request.num_results)
        # All results are academic - enrich with Semantic Scholar
        for result in raw_results:
            result["is_academic"] = True
    else:
        raw_results = await search_serper(request.query, request.num_results)
        # Detect academic content in regular results
        for result in raw_results:
            result["is_academic"] = is_academic_url(result.get("link", ""))

    # Continue with enrichment pipeline...
```

---

### Phase 4: Trust Score Integration

**File**: `api.py`

#### 4.1 Modify calculate_trust_score()

```python
def calculate_trust_score(
    domain_info: DomainInfo,
    classification: Optional[Classification],
    academic_authority: Optional[AcademicAuthority] = None  # NEW
) -> Tuple[int, List[str]]:
    """Add academic authority to trust score calculation."""

    # ... existing logic ...

    # NEW: Academic content boost/adjustment
    if academic_authority and academic_authority.score > 0:
        # High academic authority boosts trust
        if academic_authority.score >= 70:
            score += 20
        elif academic_authority.score >= 50:
            score += 15
        elif academic_authority.score >= 30:
            score += 10

        # Preprints don't get penalized but don't get full boost
        if "preprint" in academic_authority.warnings:
            score -= 5  # Slight reduction, not penalty

        # Low citations on old paper is concerning
        if "low_citations" in academic_authority.warnings:
            warnings.append("low_academic_citations")

    # ... rest of existing logic ...
```

---

### Phase 5: Processing Pipeline Integration

**File**: `api.py`

#### 5.1 Add Academic Enrichment to Pipeline

```python
async def enrich_academic_results(results: List[dict]) -> Dict[str, AcademicAuthority]:
    """
    Batch enrich academic URLs with Semantic Scholar data.
    Run in parallel with other intelligence gathering.
    """
    academic_results = {}

    tasks = []
    for result in results:
        url = result.get("link", "")
        if result.get("is_academic") or is_academic_url(url):
            identifier = extract_paper_identifier(url)
            if identifier:
                tasks.append(get_academic_data_cached(identifier, url))

    if tasks:
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for response in responses:
            if isinstance(response, tuple) and response[0]:
                url, authority = response
                academic_results[url] = authority

    return academic_results

async def get_academic_data_cached(identifier: str, url: str) -> Tuple[str, Optional[AcademicAuthority]]:
    """Get academic data with caching."""
    # Check cache first
    cached = await cache.get_cached_academic_data(identifier)
    if cached:
        return (url, AcademicAuthority(**cached))

    # Fetch from Semantic Scholar
    metadata = await get_semantic_scholar_paper(identifier)
    if metadata:
        authority = calculate_academic_authority(metadata)
        await cache.set_cached_academic_data(identifier, authority.dict())
        return (url, authority)

    return (url, None)
```

#### 5.2 Modify Main Search Flow

In `search()` endpoint, add academic enrichment to run in parallel:

```python
# Gather intelligence concurrently (existing + new)
domain_tasks = [get_domain_intelligence(url) for url in urls]
academic_task = enrich_academic_results(raw_results)  # NEW

domain_results, academic_results = await asyncio.gather(
    asyncio.gather(*domain_tasks),
    academic_task
)

# Include academic_authority in final result construction
for result in raw_results:
    url = result.get("link", "")
    academic_authority = academic_results.get(url)

    trust_score, warnings = calculate_trust_score(
        domain_info,
        classification,
        academic_authority  # NEW
    )

    verque_metadata = VerqueMetadata(
        tier=tier,
        trust_score=trust_score,
        classification=classification,
        warnings=warnings,
        academic_authority=academic_authority,  # NEW
        is_academic=result.get("is_academic", False)  # NEW
    )
```

---

### Phase 6: Publisher Database Updates

**File**: `data/publishers.json`

Add academic publishers to tier 1:

```json
{
  "tier1_domains": [
    // existing...
    "arxiv.org",
    "nature.com",
    "science.org",
    "cell.com",
    "thelancet.com",
    "nejm.org",
    "bmj.com",
    "pnas.org",
    "plos.org",
    "frontiersin.org",
    "mdpi.com",
    "springer.com",
    "wiley.com",
    "elsevier.com",
    "ieee.org",
    "acm.org"
  ]
}
```

---

## Files to Modify

| File | Changes |
|------|---------|
| `api.py` | Add models, Semantic Scholar client, academic detection, trust score integration |
| `data/publishers.json` | Add academic publisher domains |

## New API Response Fields

```json
{
  "results": [{
    "verque_metadata": {
      "trust_score": 85,
      "tier": 1,
      "is_academic": true,
      "academic_authority": {
        "score": 78.5,
        "citation_score": 65.4,
        "recency_weight": 1.2,
        "metadata": {
          "citation_count": 234,
          "influential_citation_count": 18,
          "year": 2023,
          "venue": "Nature",
          "is_preprint": false
        },
        "warnings": []
      }
    }
  }]
}
```

## New Request Option

```json
{
  "query": "transformer attention mechanism",
  "search_type": "scholar"
}
```

---

## Implementation Order

1. Add academic URL detection patterns and `is_academic_url()` function
2. Add new data models (`AcademicMetadata`, `AcademicAuthority`)
3. Implement Semantic Scholar API client with caching
4. Add `search_serper_scholar()` for scholar search mode
5. Implement `calculate_academic_authority()` with recency weighting
6. Integrate academic enrichment into main search pipeline (parallel)
7. Modify `calculate_trust_score()` to include academic signals
8. Update `publishers.json` with academic domains
9. Add `search_type` parameter to `SearchRequest`
10. Update response models to include academic fields

## Rate Limits & Costs

- **Semantic Scholar**: Free, 100 req/sec - no concern
- **Serper Scholar**: Uses existing credits, same as regular search
- **Caching**: 3-day TTL for academic data reduces API calls significantly
