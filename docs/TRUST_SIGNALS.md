# Verque Trust Signal Architecture

Internal documentation for the trust signal generation system in `api.py`.

---

## Overview

Verque generates **trust signals** to help AI applications assess the reliability of search results. The system combines multiple signal sources into a composite trust score (0-100) and tier (1-3), along with specific warnings.

### Core Philosophy

Rather than trying to determine absolute "truth," the system focuses on **source reliability indicators**—signals that correlate with trustworthy content based on empirical patterns observed in web spam, SEO manipulation, and authoritative publishing.

---

## Signal Categories

### 1. Domain Intelligence Signals

#### 1.1 Known Publisher Database (`publishers.json`)

**What it does**: Maintains curated lists of domains with known reputation characteristics.

| List | Purpose | Examples |
|------|---------|----------|
| `tier1_domains` | Major publishers with editorial oversight | nytimes.com, nature.com, docs.python.org |
| `tier1_tld_patterns` | Trusted TLD suffixes | .gov, .edu, .mil, .int |
| `high_risk_tlds` | TLDs commonly used for spam | .xyz, .top, .pw, .click |
| `ugc_platforms` | User-generated content sites | reddit.com, medium.com, stackoverflow.com |
| `tier3_domain_patterns` | Regex patterns for SEO spam domains | "best-.*-reviews", "free-.*-download" |

**Implementation**: `PublisherDB` class (lines 549-650)

**Why this approach**:
- Fast O(1) lookups for known domains
- TLD patterns catch institutional domains (.edu, .gov) without maintaining exhaustive lists
- Regex patterns identify common SEO spam naming conventions
- Trade-off: Requires manual curation; doesn't scale to long-tail domains

**Alternative approaches considered**:
- Machine learning domain classifiers (higher latency, requires training data)
- Crowd-sourced reputation (vulnerable to manipulation, slower to update)
- Pure algorithmic signals only (misses obvious known publishers)

---

#### 1.2 WHOIS Signals

**What it does**: Extracts domain registration metadata via WHOIS lookups.

| Signal | Risk Interpretation | Weight |
|--------|---------------------|--------|
| `age_days` | <90 days = very suspicious, <1 year = caution | High |
| `registration_years` | Short registration (≤1yr) = less committed | Medium |
| `days_until_expiry` | Expiring soon = potentially abandoned | Low |
| `registrar` | Some registrars correlate with spam | Medium |
| `has_privacy_protection` | Slight negative signal (hides owner) | Low |
| `is_sparse_whois` | Missing standard fields = suspicious | Medium |

**Implementation**: `_sync_whois_lookup()` (lines 681-780), `WhoisInfo` model (lines 133-140)

**Key design decisions**:

1. **Background worker pattern**: WHOIS lookups are slow (1-5s). We launch async background workers and return partial results immediately with `signals_pending: true`. Subsequent requests get cached data.

2. **7-day cache TTL**: WHOIS data changes infrequently. Long cache reduces API load and improves latency.

3. **Registrar risk scoring**: Not all registrars are equal. Budget registrars with minimal verification (Namecheap, NameSilo) see higher spam rates than enterprise registrars (MarkMonitor, CSC).

**Why this approach**:
- Domain age is one of the strongest spam predictors—new domains are 20x more likely to be spam
- Registration length signals investment/commitment (spammers register for 1 year max)
- Privacy protection alone isn't definitive but combined with other signals is informative

**Limitations**:
- WHOIS accuracy varies by TLD and registrar
- GDPR redaction affects EU domains
- Some legitimate privacy-conscious sites use protection

---

#### 1.3 DNS/Infrastructure Signals

**What it does**: Examines hosting infrastructure characteristics.

| Signal | Purpose |
|--------|---------|
| `ip_address` | Enables ASN lookup |
| `asn` | Identifies hosting provider |
| `asn_risk` | Trusted (AWS, Cloudflare) vs suspicious ASNs |
| `nameservers` | DNS provider analysis |
| `nameserver_risk` | Free/dynamic DNS = higher risk |

**Implementation**: `_sync_dns_lookup()` (lines 787-826), `get_asn_for_ip()` (lines 832-867)

**ASN lookup technique**:
Uses Team Cymru DNS-based ASN lookup—reverse IP query to `origin.asn.cymru.com`. Fast, free, reliable.

**Why this approach**:
- Hosting infrastructure reveals operational sophistication
- Spam operations concentrate on cheap/bulletproof hosting
- Major cloud providers (AWS, GCP, Cloudflare) have abuse policies that filter some bad actors
- Free/dynamic DNS services (FreeDNS, DuckDNS) enable throwaway domains

**Trusted ASN examples** (from `publishers.json`):
- AS16509, AS14618: Amazon AWS
- AS15169: Google
- AS13335: Cloudflare
- AS8075: Microsoft

---

#### 1.4 PageRank / Authority Score

**What it does**: Queries Open PageRank API for domain authority (0-10 scale).

**Implementation**: `get_pagerank()` (lines 874-903)

**Why Open PageRank**:
- Free tier (100k lookups/month)
- Approximates Google PageRank concept
- Fast API response (<500ms)

**Scoring interpretation**:
| Score | Interpretation | Trust Impact |
|-------|----------------|--------------|
| ≥6 | Major authority site | +20 |
| 4-6 | Established site | +10 |
| 2-4 | Some authority | +5 |
| <1 | Minimal link authority | -10 |

**Limitations**:
- PageRank is a popularity metric, not quality metric
- New legitimate sites have low scores
- Can be gamed with link farms (though harder now)

---

### 2. AI Classification Signals

**What it does**: Uses Claude Haiku (via AWS Bedrock) to analyze search result snippets.

**Implementation**: `classify_results_batch()` (lines 1009-1126)

**Classification outputs**:

| Field | Values | Purpose |
|-------|--------|---------|
| `content_type` | article, product_page, listicle, comparison, etc. | Content format identification |
| `intent` | informational, commercial, navigational, transactional | User intent classification |
| `affiliate_probability` | 0.0-1.0 | Likelihood of affiliate/sponsored content |
| `ai_generated_probability` | 0.0-1.0 | Likelihood of AI-generated content |
| `quality_estimate` | high, medium, low | Subjective quality assessment |

**Batch processing design**:
- Results are sent in a single prompt for efficiency
- Known tier-1 publishers skip classification (saves cost)
- Results cached by URL hash for 1 hour

**Why LLM classification**:
- Handles nuanced pattern recognition humans use
- Adapts to evolving spam tactics
- Identifies affiliate content disguised as reviews
- Detects AI-generated content patterns (repetitive structure, hedging language)

**Prompt strategy**:
The prompt asks for JSON output with specific fields. Model returns array matching input order. Markdown code block stripping handles formatting variations.

**Trade-offs**:
- Adds ~300-800ms latency per batch
- Costs credits (usage-based pricing)
- Model can hallucinate or be inconsistent
- Snippet-only analysis misses full page context

---

### 3. Content Pattern Signals

**What it does**: Regex-based detection of spam patterns in titles/snippets.

**Implementation**: `has_spam_keywords()` in PublisherDB (lines 616-620)

**Patterns detected** (from `publishers.json`):
```regex
\bfree\b.*\bdownload\b
\bbest\b.*\b\d{4}\b.*\breview
\btop\s*\d+\b.*\bbest\b
\bcheap\b.*\bonline\b
\bbuy\b.*\bnow\b.*\bfree\b
```

**Why regex over ML**:
- Zero latency
- Deterministic/explainable
- Easy to update as patterns emerge
- No training data needed

---

## Trust Score Calculation

**Implementation**: `calculate_trust_score()` (lines 1132-1223)

### Scoring Algorithm

Starts at neutral **50**, then applies adjustments:

```
Base: 50

Known publisher: return 85 immediately

Domain Age:
  <90 days:   -30
  <1 year:    -15
  >5 years:   +15
  >10 years:  +20

Registration Length:
  ≤1 year:    -10
  ≥5 years:   +10

Registrar Risk:
  trusted:    +15
  suspicious: -15

Privacy Protection: -5
Sparse WHOIS:       -10

TLD Risk:
  high:       -25
  trusted:    +20

ASN Risk:
  trusted:    +10
  suspicious: -15

Nameserver Risk:
  suspicious: -10

PageRank:
  ≥6:         +20
  ≥4:         +10
  ≥2:         +5
  <1:         -10

UGC Platform: -5

Affiliate Probability:
  >0.8:       -20
  >0.5:       -10

AI Generated Probability:
  >0.8:       -25
  >0.5:       -15

Quality Estimate:
  high:       +15
  low:        -20

Final: clamp(0, 100)
```

### Tier Determination

**Implementation**: `determine_tier()` (lines 1226-1243)

```
Tier 1: Known publisher OR score ≥ 70
Tier 2: Score 40-69
Tier 3: Score < 40 OR (high-risk TLD + domain < 6 months)
```

---

## Warning Generation

**Implementation**: `generate_warnings()` (lines 1246-1317)

Returns array of warning codes:

| Warning | Trigger |
|---------|---------|
| `new_domain` | Age < 90 days |
| `young_domain` | Age < 1 year |
| `suspicious_tld` | High-risk TLD |
| `suspicious_registrar` | Known spam-associated registrar |
| `short_registration` | Registered for ≤1 year |
| `expiring_soon` | Expires in <90 days |
| `sparse_whois` | Missing standard WHOIS fields |
| `suspicious_hosting` | ASN associated with abuse |
| `suspicious_nameserver` | Free/dynamic DNS |
| `low_authority` | PageRank < 1 |
| `keyword_stuffed_domain` | Domain matches spam patterns |
| `keyword_stuffed_snippet` | Snippet matches spam patterns |
| `likely_ai_generated` | AI probability > 0.7 |
| `likely_affiliate` | Affiliate probability > 0.8 |
| `low_quality_content` | Quality estimate = low |
| `signals_pending` | Background lookup incomplete |

---

## Alternative Techniques Not Implemented (Yet)

### 1. Content Analysis (Full Page)

**What it would do**: Fetch and analyze full page content, not just snippets.

**Benefits**:
- More accurate affiliate detection (link analysis)
- Better AI content detection
- Fact extraction for verification

**Why not implemented**:
- Significantly increases latency (page fetch + parse)
- Legal concerns (scraping at scale)
- Cost (LLM tokens for full pages)

**Potential approach**: On-demand deep analysis endpoint for specific URLs.

---

### 2. Link Graph Analysis

**What it would do**: Analyze inbound/outbound link patterns.

**Benefits**:
- Detect link farms/PBNs
- Identify citation patterns (authoritative sources cite each other)
- Find affiliate link concentrations

**Why not implemented**:
- Requires web crawl infrastructure
- Index maintenance is expensive
- PageRank API provides partial proxy

**Potential approach**: Partner with existing link index (Ahrefs, Moz, Majestic).

---

### 3. Historical WHOIS / Domain History

**What it would do**: Track domain ownership changes over time.

**Benefits**:
- Detect expired/dropped domains repurposed for spam
- Identify ownership transfer patterns

**Why not implemented**:
- Historical WHOIS data is expensive (DomainTools, etc.)
- Complex to maintain

---

### 4. Social Proof Signals

**What it would do**: Analyze social media shares, engagement, brand mentions.

**Benefits**:
- Organic sharing indicates value
- Brand consistency across platforms

**Why not implemented**:
- Social APIs are restrictive/expensive
- Engagement can be purchased
- Not directly correlated with content quality

---

### 5. SSL/TLS Certificate Analysis

**What it would do**: Examine certificate type and issuer.

**Benefits**:
- EV certificates require organization verification
- DV certificates are easy to obtain for spam

**Why not implemented**:
- Let's Encrypt democratized free certificates
- Certificate type is weak signal now
- Most legitimate sites use DV

---

### 6. Archive/Historical Content Analysis

**What it would do**: Compare current content to Wayback Machine archives.

**Benefits**:
- Detect content changes over time
- Identify hijacked domains
- Verify content consistency

**Why not implemented**:
- Internet Archive rate limits
- Many pages aren't archived
- Adds significant latency

---

## Performance Architecture

### Caching Strategy

| Data Type | TTL | Rationale |
|-----------|-----|-----------|
| WHOIS | 7 days | Domain registration rarely changes |
| DNS | 1 day | Infrastructure changes occasionally |
| PageRank | 7 days | Authority scores are stable |
| Classification | 1 hour | Content at URLs can change |

### Concurrency Model

```
Request arrives
  ├── Serper API call (blocking)
  └── For each result (concurrent):
        ├── Domain info lookup
        │     ├── Check publisher DB (instant)
        │     ├── WHOIS lookup (cached or background worker)
        │     ├── DNS lookup (cached or sync)
        │     ├── ASN lookup (cached or sync)
        │     └── PageRank lookup (cached or async HTTP)
        └── AI classification (batch all non-tier1)
```

---

## Next Steps

### Short-term (Low Effort)

1. **Expand publisher database**: Add more tier-1 domains, especially non-English authoritative sources.

2. **Tune scoring weights**: A/B test different weight configurations against human ratings.

3. **Add more regex patterns**: Track emerging spam patterns and add to detection.

4. **Classification prompt improvements**: Refine prompt for better affiliate/AI detection accuracy.

### Medium-term (Moderate Effort)

5. **Content verification endpoint**: New endpoint that fetches full page, extracts claims, cross-references.

6. **User feedback loop**: Allow API consumers to report false positives/negatives; use for model improvement.

7. **Historical data**: Track trust scores over time per domain; detect reputation changes.

8. **Blocklist integration**: Integrate with public blocklists (Google Safe Browsing, PhishTank).

### Long-term (High Effort)

9. **Custom ML models**: Train domain classifier on proprietary dataset of spam/quality labels.

10. **Link analysis**: Build or license link graph data for citation/backlink analysis.

11. **Real-time content verification**: LLM-powered fact-checking against known authoritative sources.

---

## Resources

### Domain/WHOIS Analysis
- [ICANN WHOIS Accuracy Studies](https://www.icann.org/resources/pages/whois-accuracy-2013-03-21-en)
- [python-whois library](https://pypi.org/project/python-whois/)
- [Team Cymru IP-to-ASN mapping](https://www.team-cymru.com/ip-asn-mapping)

### Web Spam Research
- [Google Web Spam Report](https://developers.google.com/search/docs/essentials/spam-policies)
- ["Web Spam Taxonomy"](https://airweb.cse.lehigh.edu/2005/gyongyi.pdf) - Stanford/Yahoo (2005, foundational)
- [SpamAssassin Rules](https://spamassassin.apache.org/full/3.4.x/doc/Mail_SpamAssassin_Conf.html) - Email spam patterns that transfer to web

### Trust/Reputation Systems
- [EigenTrust](https://nlp.stanford.edu/pubs/eigentrust.pdf) - P2P reputation algorithm
- [PageRank original paper](http://ilpubs.stanford.edu:8090/422/1/1999-66.pdf)
- [Open PageRank API](https://www.domcop.com/openpagerank/)

### AI Content Detection
- [GPTZero](https://gptzero.me/) - AI content detection
- [Originality.ai](https://originality.ai/) - Commercial AI detection
- [DetectGPT paper](https://arxiv.org/abs/2301.11305) - Academic approach

### Affiliate/Sponsored Content
- [FTC Endorsement Guidelines](https://www.ftc.gov/business-guidance/resources/ftc-endorsement-guides-what-people-are-asking)
- [Google's stance on affiliate content](https://developers.google.com/search/docs/fundamentals/creating-helpful-content)

### APIs Used
- [Serper API](https://serper.dev/) - Google search results
- [AWS Bedrock](https://aws.amazon.com/bedrock/) - Claude Haiku access
- [Open PageRank](https://www.domcop.com/openpagerank/documentation) - Domain authority

---

## Code Reference

| Component | Location |
|-----------|----------|
| Trust score calculation | `api.py:1132-1223` |
| Tier determination | `api.py:1226-1243` |
| Warning generation | `api.py:1246-1317` |
| WHOIS lookup | `api.py:681-780` |
| DNS lookup | `api.py:787-826` |
| ASN lookup | `api.py:832-867` |
| PageRank lookup | `api.py:874-903` |
| AI classification | `api.py:1009-1126` |
| Publisher database | `api.py:549-650` |
| Domain intelligence orchestration | `api.py:910-994` |
| Search endpoint (integration) | `api.py:1379-1558` |
| Publisher data | `data/publishers.json` |
