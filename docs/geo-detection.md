# GEO Detection

Verque detects **Generative Engine Optimization (GEO)**—content specifically crafted to get cited by AI answer engines like Perplexity, ChatGPT Search, and Google AI Overviews, rather than to inform human readers.

## What is GEO?

GEO is the AI-era equivalent of SEO spam. While traditional SEO manipulation targets search engine crawlers, GEO targets the large language models that power AI answer engines. GEO-optimized content often:

- Uses phrases designed to sound authoritative without substance
- Structures content as Q&A even when unnatural
- Repeats query keywords unnaturally to maximize relevance scoring
- Mimics the citation patterns that LLMs favor

The result: AI systems cite low-quality sources that were engineered to be cited, creating a feedback loop that amplifies manipulation.

## GEO Fields in Search Results

Every search result includes GEO detection in the `verque.classification` object:

```json
{
  "title": "What is Blockchain? Complete Guide 2024",
  "url": "https://example.com/blockchain-guide",
  "verque": {
    "tier": 2,
    "trust_score": 45,
    "classification": {
      "content_type": "article",
      "intent": "informational",
      "geo_optimization_probability": 0.75,
      "geo_signals": ["citation_bait", "qa_format_overuse"]
    },
    "warnings": [
      "likely_geo_optimized",
      "geo_citation_bait",
      "geo_qa_format_overuse"
    ]
  }
}
```

### `geo_optimization_probability`

A score from 0.0 to 1.0 indicating the likelihood that content was optimized for AI citation engines rather than human readers.

| Score | Interpretation |
|-------|----------------|
| 0.0 - 0.3 | Unlikely to be GEO-optimized |
| 0.3 - 0.5 | Some GEO signals present |
| 0.5 - 0.7 | Moderate GEO optimization |
| 0.7 - 1.0 | Likely GEO-optimized content |

### `geo_signals`

An array of specific GEO tactics detected in the content:

| Signal | Description |
|--------|-------------|
| `excessive_schema_markup` | Heavy structured data formatting designed for rich snippets |
| `qa_format_overuse` | Content structured as question-answer even when unnatural for the topic |
| `citation_bait` | Phrases like "according to experts", "studies show", "research indicates" without specific citations |
| `llm_friendly_phrasing` | Unnaturally direct definitions and summary-style answers optimized for extraction |
| `authority_mimicry` | Mimics authoritative tone ("ultimate guide", "everything you need to know") without substantive content |
| `keyword_density_optimized` | Query terms repeated unnaturally often throughout the content |

## GEO Warnings

When GEO is detected, warnings are added to the `verque.warnings` array:

- `likely_geo_optimized` — Appears when `geo_optimization_probability > 0.7`
- `geo_{signal}` — One warning per detected signal (e.g., `geo_citation_bait`, `geo_qa_format_overuse`)

## Trust Score Impact

GEO detection affects trust scores:

| Condition | Trust Score Adjustment |
|-----------|----------------------|
| `geo_optimization_probability > 0.8` | -25 points |
| `geo_optimization_probability > 0.5` | -15 points |
| 3+ GEO signals detected | Additional -10 points |

A heavily GEO-optimized result can lose up to 35 points, often dropping it from Tier 1 to Tier 2 or Tier 3.

## Example: Filtering GEO Content

Filter out likely GEO-optimized results in your application:

```python
results = verque_search("best project management software")

# Filter out GEO-optimized content
clean_results = [
    r for r in results
    if r["verque"]["classification"]["geo_optimization_probability"] < 0.5
]

# Or filter by specific signals
no_citation_bait = [
    r for r in results
    if "citation_bait" not in r["verque"]["classification"]["geo_signals"]
]
```

## Why This Matters

AI answer engines are increasingly the front door to information. When they cite GEO-manipulated content:

1. **Users get lower-quality answers** — Content optimized for citation isn't optimized for accuracy
2. **Legitimate sources get buried** — GEO-gamed content crowds out genuine expertise
3. **Manipulation scales** — Unlike traditional SEO, GEO manipulation is harder to detect and easier to automate

Verque's GEO detection helps you build AI applications that resist this manipulation vector.
