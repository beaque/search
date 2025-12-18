# Verque: Intelligent Search API for AI Applications

## Overview

Verque is a search API designed for AI/LLM tool use that wraps existing SERP providers (starting with Serper) and adds an intelligence layer. While Serper and similar APIs return raw search results, Verque enriches each result with domain-level trust signals, content classification, and quality indicators—giving LLMs and AI agents the context they need to make informed decisions about source reliability.

### The Problem

When LLMs use search tools, they receive raw results with no way to distinguish between:
- A well-researched article from an established publication
- A content farm spun up last month with AI-generated text
- SEO spam designed to rank for specific queries
- Legitimate but low-authority user-generated content

This leads to "garbage in, garbage out" situations where LLMs confidently cite unreliable sources, hallucinate based on poor inputs, or treat all sources as equally credible.

### The Solution

Verque sits between the raw SERP provider and the AI application, adding:
- **Domain Intelligence**: Trust signals based on domain age, authority, and reputation
- **Content Classification**: AI-powered analysis of what type of content each result represents
- **Quality Indicators**: Warnings and flags for potentially problematic sources
- **Source Tiering**: Simple tier system (1-3) for quick filtering decisions

---

## Market Position

| Feature | Serper | SerpApi | Tavily | Verque |
|---------|--------|---------|--------|--------|
| Raw SERP data | ✅ | ✅ | ✅ | ✅ |
| Speed | Fast | Fast | Fast | Fast (async enrichment) |
| Price per 1K | $0.30-1.00 | $10-15 | ~$1.50 | $2-5 (TBD) |
| Domain trust signals | ❌ | ❌ | ❌ | ✅ |
| Source tiering | ❌ | ❌ | ❌ | ✅ |
| AI content classification | ❌ | ❌ | Basic | ✅ |
| Quality warnings | ❌ | ❌ | ❌ | ✅ |
| Optimized for LLM tool use | ❌ | ❌ | ✅ | ✅ |

**Target customers**: Developers building AI agents, RAG pipelines, search-augmented chatbots, and any application where LLMs consume web search results.

---

## Architecture (MVP)

```
User Request
     │
     ▼
┌─────────────────┐
│   Verque API    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     Serper      │  ← Raw SERP data
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────┐
│       Intelligence Layer            │
│                                     │
│  ┌─────────────┐  ┌──────────────┐  │
│  │   Domain    │  │     AI       │  │
│  │ Intelligence│  │Classification│  │
│  │  (cached)   │  │  (per-query) │  │
│  └─────────────┘  └──────────────┘  │
│                                     │
└────────┬────────────────────────────┘
         │
         ▼
   Enriched Response
```

### Why Wrap Serper?

- Proven reliability and speed
- Low cost ($0.001/query or less at scale)
- Focus our effort on the intelligence layer, not SERP scraping
- Can swap underlying provider later if needed

---

## Intelligence Layer Components

### 1. Domain Intelligence (Cached)

Domain-level signals are high-value and highly cacheable—a domain's age and reputation don't change query-to-query.

#### WHOIS / Registration Data
- **Domain age**: When was the domain registered? New domains (<90 days) are higher risk for spam/SEO manipulation.
- **Registration length**: Legitimate businesses register domains for multiple years. Single-year registrations can indicate throwaway spam domains.
- **Registrar patterns**: Some registrars are disproportionately used for spam operations.
- **Privacy protection**: Not inherently bad, but a signal when combined with other factors.

#### Domain Authority / Backlink Profile
- **Authority score**: How well-linked and established is this domain? Scores from services like Moz, Ahrefs, or open alternatives.
- **Referring domains**: How many unique sites link to this domain?
- **Organic traffic estimates**: Does this site have real visitors, or is it a link farm?

#### Domain Classification / Category
- **Site type**: News, blog, ecommerce, forum, government, academic, corporate, affiliate, documentation
- **UGC platform detection**: Is this medium.com, reddit.com, substack.com where content quality varies by author?
- **Aggregator detection**: Sites that scrape/rewrite content from other sources

#### Known Publisher Database
A curated, maintained database of:
- **Tier 1 domains**: Major news outlets, government sites (.gov), educational institutions (.edu), authoritative reference sites, official documentation
- **Tier 3 patterns**: Known content farms, spam domain patterns, expired domain spam networks
- **UGC platforms**: Sites where content is user-generated and quality varies

This database is a core product asset and will be refined continuously based on user feedback and quality audits.

#### Technical / Infrastructure Signals
- **Hosting provider**: Legitimate sites vs. bulletproof hosting known for spam
- **SSL certificate**: Valid? Issuer? (Let's Encrypt is fine, but combined with a brand-new domain it's a signal)
- **Shared hosting indicators**: Thousands of sites on the same IP often indicates low-quality operations
- **CDN usage**: Legitimate sites often use CDNs

### 2. AI Classification (Per-Query)

For signals that require understanding the actual content, we use a fast, cheap LLM call (e.g., Claude Haiku or GPT-4o-mini) to classify each result based on its title, snippet, and URL.

#### What AI Classification Provides
- **Content type**: Article, product page, forum post, news, documentation, listicle, comparison, tutorial
- **Likely intent**: Informational, commercial, navigational
- **Affiliate signals**: Probability this is affiliate/sponsored content
- **AI-generated signals**: Probability the content is AI-generated (based on snippet patterns)
- **Quality estimate**: High/medium/low based on snippet substance

#### Why This Matters
Heuristics can catch obvious spam, but AI classification catches nuance:
- A legitimate-looking domain with thin, AI-generated content
- Affiliate content disguised as editorial
- The difference between a genuine review and a "best X for Y" SEO play

#### Cost Control
- Use the cheapest model that works (Haiku-class)
- Batch classification calls for efficiency
- Cache results for identical URLs within a time window
- Skip classification for known Tier 1 domains (unnecessary cost)

---

## Source Tiering System

Every result gets assigned a tier for quick filtering:

| Tier | Description | Examples |
|------|-------------|----------|
| **Tier 1** | High-trust, authoritative sources | Major news (NYT, BBC, Reuters), .gov, .edu, official docs, established reference sites |
| **Tier 2** | Generally reliable, but verify | Mid-authority blogs, UGC platforms (quality varies), corporate sites, smaller news outlets |
| **Tier 3** | Low trust, use with caution | New domains, detected spam patterns, thin content, high affiliate signals |

LLM applications can:
- Filter to Tier 1 only for high-stakes queries
- Include Tier 2 for broader coverage
- Flag or exclude Tier 3 results

---

## Example API Output

> **Note**: The following JSON structure is illustrative and not a final specification. The actual API response format will be refined during development.

### Standard Serper Response

```json
{
  "searchParameters": {
    "q": "best project management software 2025"
  },
  "organic": [
    {
      "title": "Best Project Management Software 2025 | TechRadar",
      "link": "https://techradar.com/best/project-management-software",
      "snippet": "We've tested and reviewed dozens of project management tools to find the best options for teams of all sizes...",
      "position": 1
    },
    {
      "title": "TOP 10 Best PM Software [2025 Reviews & Comparison]",
      "link": "https://pm-tools-best-reviews.xyz/top-10-best",
      "snippet": "Best project management software best PM tools best project management best software for projects...",
      "position": 2
    }
  ]
}
```

### Verque Enriched Response

```json
{
  "query": "best project management software 2025",
  "results": [
    {
      "title": "Best Project Management Software 2025 | TechRadar",
      "url": "https://techradar.com/best/project-management-software",
      "snippet": "We've tested and reviewed dozens of project management tools to find the best options for teams of all sizes...",
      "position": 1,
      
      "verque": {
        "tier": 1,
        "trust_score": 82,
        
        "domain": {
          "name": "techradar.com",
          "age_years": 18,
          "category": "technology_news",
          "authority_score": 78,
          "is_known_publisher": true,
          "is_ugc_platform": false
        },
        
        "classification": {
          "content_type": "comparison_article",
          "intent": "commercial_informational",
          "affiliate_probability": 0.7,
          "ai_generated_probability": 0.1,
          "quality_estimate": "high"
        },
        
        "warnings": []
      }
    },
    {
      "title": "TOP 10 Best PM Software [2025 Reviews & Comparison]",
      "url": "https://pm-tools-best-reviews.xyz/top-10-best",
      "snippet": "Best project management software best PM tools best project management best software for projects...",
      "position": 2,
      
      "verque": {
        "tier": 3,
        "trust_score": 15,
        
        "domain": {
          "name": "pm-tools-best-reviews.xyz",
          "age_days": 47,
          "category": "unknown",
          "authority_score": null,
          "is_known_publisher": false,
          "is_ugc_platform": false
        },
        
        "classification": {
          "content_type": "listicle",
          "intent": "commercial",
          "affiliate_probability": 0.95,
          "ai_generated_probability": 0.85,
          "quality_estimate": "low"
        },
        
        "warnings": [
          "new_domain",
          "suspicious_tld",
          "keyword_stuffed_domain",
          "keyword_stuffed_snippet",
          "likely_ai_generated"
        ]
      }
    }
  ],
  
  "meta": {
    "enrichment_level": "standard",
    "processing_time_ms": 450,
    "cached_domains": 1,
    "ai_classifications": 2
  }
}
```

---

## MVP Implementation Plan

### Phase 1: Foundation (Week 1-2)

**Goal**: Working API that wraps Serper and adds basic domain intelligence.

- [ ] Set up API infrastructure (FastAPI or similar)
- [ ] Implement Serper integration (pass-through that works)
- [ ] Build domain intelligence cache layer
- [ ] Implement WHOIS lookups with caching
- [ ] Create initial known publisher database (~200 Tier 1, ~100 Tier 3 patterns)
- [ ] Implement basic tiering logic based on domain signals
- [ ] Deploy MVP endpoint

**Deliverable**: API that returns Serper results + domain age + tier + basic warnings

### Phase 2: AI Classification (Week 3-4)

**Goal**: Add AI-powered content classification to each result.

- [ ] Design classification prompt for snippet analysis
- [ ] Implement LLM integration (Haiku or GPT-4o-mini)
- [ ] Add batching for efficiency
- [ ] Implement result caching for identical URLs
- [ ] Add classification fields to API response
- [ ] Test and refine classification accuracy

**Deliverable**: Full "standard" enrichment level working

### Phase 3: Refinement (Week 5-6)

**Goal**: Improve accuracy, add features based on early feedback.

- [ ] Expand known publisher database based on real queries
- [ ] Add domain authority integration (Open PageRank or similar)
- [ ] Implement technical signal checks (DNS, hosting)
- [ ] Add filtering options to API (min_tier, exclude_warnings, etc.)
- [ ] Build feedback mechanism for users to report bad classifications
- [ ] Documentation and examples

**Deliverable**: Production-ready API with documentation

---

## Pricing Model (Draft)

| Tier | Price per 1K queries | Includes |
|------|---------------------|----------|
| Free | $0 | 500 queries/month, standard enrichment |
| Starter | $29/month | 10K queries, standard enrichment |
| Pro | $99/month | 50K queries, standard enrichment, priority support |
| Scale | Custom | Volume pricing, SLA, dedicated support |

**Cost structure per query (estimated)**:
- Serper: ~$0.001
- AI classification: ~$0.0001
- Domain lookups: ~$0.0001 (amortized with caching)
- **Total COGS: ~$0.0012-0.0015**
- **Target price: $0.003-0.005** (50-70% margin)

---

## Success Metrics

- **Adoption**: Number of API users, queries per day
- **Quality**: User feedback on tier accuracy, classification accuracy
- **Differentiation**: Can users measurably improve their LLM outputs using Verque vs raw Serper?
- **Retention**: Do users stick after trial period?

---

## Open Questions

- Exact pricing tiers and free tier limits
- Whether to offer a "deep" enrichment level (fetches full pages) in MVP or later
- Which domain authority data source to use (cost vs. coverage tradeoff)
- API authentication method (API keys, OAuth, etc.)
- Rate limiting strategy

---

## Appendix A: Why This Matters for LLMs

Research shows that LLMs and users often misjudge source credibility:

> "User preferences are influenced by the number of citations, even when the cited content does not directly support the attributed claims, uncovering a gap between perceived and actual credibility."

And the threat landscape is evolving:

> "SEO poisoning attacks have increased 60% in six months, with 15,000+ sites compromised in major campaigns targeting enterprise users."

By providing trust signals at the API level, Verque helps AI applications make better decisions about which sources to use, cite, and trust—without requiring each developer to build their own domain intelligence infrastructure.

---

## Appendix B: Comprehensive Domain & Technical Signals Reference

This appendix catalogs all potential signals for domain intelligence. Not all signals will be implemented in MVP—this serves as a reference for future development and prioritization.

### WHOIS / Registration Signals

| Signal | Description | Risk Indicator |
|--------|-------------|----------------|
| Domain age | Days since domain registration | <90 days = high risk, <365 days = elevated |
| Registration length | How long domain is registered for | 1-year registration = more suspicious than 5+ years |
| Expiration proximity | Days until domain expires | Expiring soon + other signals = throwaway domain |
| Registrar | Which registrar was used | Some registrars are disproportionately used for spam |
| Privacy protection | WHOIS privacy service enabled | Not inherently bad, but a signal when combined |
| Sparse WHOIS data | Missing org/name/contact fields | Can indicate hastily registered spam domains |
| Recent transfer | Domain changed hands recently | Expired domain spam networks buy old domains for their authority |

### DNS / Infrastructure Signals

| Signal | Description | Risk Indicator |
|--------|-------------|----------------|
| DNS age | When DNS records were first seen | May differ from WHOIS if domain was transferred/parked |
| IP geolocation | Where the server is hosted | Certain regions have higher spam concentrations |
| ASN / Network | Which network hosts the site | Some ASNs are known for bulletproof hosting / spam |
| Shared hosting density | How many domains on same IP | Thousands of sites = often low-quality hosting |
| Nameserver reputation | Which DNS provider is used | Some free DNS providers are spam-heavy |
| DNS record history | How often records change | Frequent changes can indicate malicious activity |

### TLD (Top-Level Domain) Signals

| Signal | Description | Risk Indicator |
|--------|-------------|----------------|
| TLD risk category | Which TLD the domain uses | .xyz, .top, .pw, .club, .work = higher spam rates |
| Country-code TLD mismatch | .de domain with English content targeting US | Can indicate domain shopping for SEO |
| New gTLD | Recently introduced TLDs | Some newer TLDs have less oversight |

**High-risk TLDs** (based on spam research): `.xyz`, `.top`, `.pw`, `.club`, `.work`, `.date`, `.loan`, `.download`, `.win`, `.bid`, `.stream`

**Trusted TLDs**: `.gov`, `.edu`, `.mil`, `.int` (restricted registration)

### SSL / Certificate Signals

| Signal | Description | Risk Indicator |
|--------|-------------|----------------|
| SSL validity | Is certificate valid and current | Invalid/expired = obvious red flag |
| Certificate issuer | Who issued the cert | Let's Encrypt is fine, but combined with new domain = signal |
| Certificate age | When cert was first issued | Brand new cert + new domain = very new operation |
| Certificate type | DV vs OV vs EV | EV requires organization validation (higher trust) |

### Content Delivery / Technical Signals

| Signal | Description | Risk Indicator |
|--------|-------------|----------------|
| CDN usage | Site uses Cloudflare, Fastly, etc. | Legitimate sites often use CDNs |
| Hosting provider | AWS, GCP, known hosts vs. obscure | Bulletproof hosting = red flag |
| Response headers | Server signatures, security headers | Missing security headers on "professional" site = signal |
| Page load behavior | JavaScript-heavy, delayed content | Can indicate cloaking or manipulation |

### Redirect / Cloaking Signals

| Signal | Description | Risk Indicator |
|--------|-------------|----------------|
| Redirect chain length | How many redirects before final URL | Long chains often hide malicious destinations |
| Redirect domain mismatch | Redirects to completely different domain | SEO spam technique |
| User-agent cloaking | Different content for bots vs browsers | Major spam/SEO manipulation technique |
| Referer-based cloaking | Different content based on referrer | Shows spam content only to search traffic |
| Geographic cloaking | Different content by visitor location | Can indicate targeted attacks |

### Threat Intelligence Signals

| Signal | Description | Source |
|--------|-------------|--------|
| Google Safe Browsing | Known malware/phishing | Google Safe Browsing API |
| PhishTank | Known phishing URLs | PhishTank API |
| URLhaus | Malware distribution URLs | abuse.ch |
| Spam domain lists | Known spam operations | Spamhaus, SURBL |
| SEO spam reports | Reported manipulation | Community/proprietary |

### Authority / Reputation Signals

| Signal | Description | Source |
|--------|-------------|--------|
| Domain Authority (DA) | Moz's authority metric | Moz API |
| Domain Rating (DR) | Ahrefs' authority metric | Ahrefs API |
| Authority Score | SEMrush's combined metric | SEMrush API |
| Open PageRank | Open-source PageRank estimate | Open PageRank API |
| Referring domains | Unique sites linking to domain | Various |
| Organic traffic estimate | Estimated monthly visitors | Various |
| Spam score | Likelihood of being spam | Moz Spam Score |

### Content / On-Page Signals (Requires Fetching)

| Signal | Description | Risk Indicator |
|--------|-------------|----------------|
| Content-snippet mismatch | Page content differs from search snippet | Cloaking or bait-and-switch |
| Keyword density | Abnormal keyword repetition | Keyword stuffing |
| Ads-to-content ratio | More ads than content | Low-quality monetization play |
| Outbound link patterns | All links go to same affiliate | Affiliate spam |
| Author presence | Real byline vs anonymous | Anonymous = lower accountability |
| Publication date | When content was published | Stale content presented as current |
| Content depth | Word count, structure, substance | Thin content = low quality |

### Implementation Priority

**MVP (Phase 1-2)**:
- Domain age (WHOIS)
- Registration length
- TLD risk scoring
- Known publisher database
- Basic authority score (Open PageRank or similar)
- AI classification of snippets

**Phase 3+**:
- Full WHOIS analysis (registrar, privacy, sparse data)
- DNS/infrastructure signals
- Threat intelligence integration
- Redirect chain detection

**Future / Premium**:
- Real-time cloaking detection (fetch as bot + browser)
- Full page content analysis
- Historical domain reputation tracking
- Custom threat feeds
