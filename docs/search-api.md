# Verque Search API Documentation

Base URL: `https://api.verque.app`

## Authentication

All requests require an API key passed in the `X-API-Key` header.

```bash
curl -X POST https://api.verque.app/search \
  -H "Content-Type: application/json" \
  -H "X-API-Key: vq_your_api_key_here" \
  -d '{"query": "your search query"}'
```

## Search Endpoint

### `POST /search`

Performs an intelligent search with domain intelligence, AI classification, trust scoring, and source tiering.

### Request Body

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `query` | string | Yes | - | Search query (1-500 characters) |
| `num_results` | integer | No | 10 | Number of results to return (1-100) |
| `ai_classification` | boolean | No | true | Enable AI content classification |
| `verify_claims` | boolean | No | false | Enable claim verification (not yet implemented) |

### Example Request

```json
{
  "query": "best practices for API design",
  "num_results": 10,
  "ai_classification": true
}
```

### Response

```json
{
  "query": "best practices for API design",
  "results": [
    {
      "title": "REST API Design Best Practices",
      "url": "https://example.com/api-design",
      "snippet": "Learn the best practices for designing RESTful APIs...",
      "position": 1,
      "verque": {
        "tier": 1,
        "trust_score": 85,
        "classification": {
          "content_type": "tutorial",
          "intent": "informational",
          "affiliate_probability": 0.0,
          "ai_generated_probability": 0.1,
          "quality_estimate": "high"
        },
        "warnings": []
      }
    }
  ],
  "credits": {
    "credits_used": 2.0,
    "breakdown": {
      "base": 1,
      "classification": 1,
      "verification": 0
    }
  },
  "meta": {
    "enrichment_level": "standard",
    "processing_time_ms": 450,
    "results_count": 10,
    "ai_classifications": 8,
    "signals_pending": 0,
    "timings": {
      "serper_ms": 200,
      "domain_intel_ms": 150,
      "classification_ms": 100
    }
  }
}
```

### Response Fields

#### Result Object

| Field | Type | Description |
|-------|------|-------------|
| `title` | string | Page title |
| `url` | string | Full URL of the result |
| `snippet` | string | Text snippet from the page |
| `position` | integer | Position in search results |
| `verque` | object | Verque enrichment metadata |

#### Verque Metadata

| Field | Type | Description |
|-------|------|-------------|
| `tier` | integer | Source tier (1=trusted, 2=standard, 3=low trust) |
| `trust_score` | integer | Trust score (0-100) |
| `classification` | object | AI content classification |
| `warnings` | array | List of warning messages |

#### Classification Object

| Field | Type | Description |
|-------|------|-------------|
| `content_type` | string | Type of content (e.g., "article", "tutorial", "product", "news") |
| `intent` | string | Content intent (e.g., "informational", "commercial", "transactional") |
| `affiliate_probability` | float | Probability of affiliate content (0.0-1.0) |
| `ai_generated_probability` | float | Probability of AI-generated content (0.0-1.0) |
| `quality_estimate` | string | Quality estimate ("low", "medium", "high") |

#### Credits Object

| Field | Type | Description |
|-------|------|-------------|
| `credits_used` | float | Total credits consumed |
| `breakdown` | object | Credit breakdown by feature |

## Credit Pricing

| Feature | Cost |
|---------|------|
| Base search | 1 credit |
| AI classification (first 5 results) | 1 credit |
| AI classification (additional results) | +0.2 credits each |
| Claim verification | Free (not yet implemented) |

**Example:** A search for 10 results with AI classification enabled costs:
- Base: 1 credit
- Classification: 1 + (5 × 0.2) = 2 credits
- **Total: 3 credits**

## Error Responses

### 401 Unauthorized

```json
{
  "detail": "Missing API key. Include 'X-API-Key' header."
}
```

```json
{
  "detail": "Invalid API key."
}
```

### 402 Payment Required

```json
{
  "detail": {
    "error": "insufficient_credits",
    "credits_required": 3.0,
    "credits_available": 1.5,
    "message": "This request costs 3.0 credits but you only have 1.5. Please add more credits."
  }
}
```

### 422 Validation Error

```json
{
  "detail": [
    {
      "loc": ["body", "query"],
      "msg": "String should have at least 1 character",
      "type": "string_too_short"
    }
  ]
}
```

## Code Examples

### Python

```python
import requests

response = requests.post(
    "https://api.verque.app/search",
    headers={
        "Content-Type": "application/json",
        "X-API-Key": "vq_your_api_key_here"
    },
    json={
        "query": "machine learning tutorials",
        "num_results": 5,
        "ai_classification": True
    }
)

data = response.json()
for result in data["results"]:
    print(f"[Tier {result['verque']['tier']}] {result['title']}")
    print(f"  Trust Score: {result['verque']['trust_score']}")
    print(f"  URL: {result['url']}")
```

### JavaScript (Node.js)

```javascript
const response = await fetch("https://api.verque.app/search", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": "vq_your_api_key_here"
  },
  body: JSON.stringify({
    query: "machine learning tutorials",
    num_results: 5,
    ai_classification: true
  })
});

const data = await response.json();
data.results.forEach(result => {
  console.log(`[Tier ${result.verque.tier}] ${result.title}`);
  console.log(`  Trust Score: ${result.verque.trust_score}`);
  console.log(`  URL: ${result.url}`);
});
```

### cURL

```bash
curl -X POST https://api.verque.app/search \
  -H "Content-Type: application/json" \
  -H "X-API-Key: vq_your_api_key_here" \
  -d '{
    "query": "machine learning tutorials",
    "num_results": 5,
    "ai_classification": true
  }'
```

## Source Tiering

Results are categorized into three tiers based on domain intelligence and trust signals:

| Tier | Description | Examples |
|------|-------------|----------|
| **Tier 1** | Trusted, authoritative sources | Major news outlets, government sites (.gov), educational institutions (.edu), established publishers |
| **Tier 2** | Standard sources | Most legitimate websites with normal trust signals |
| **Tier 3** | Low trust sources | New domains, high-risk TLDs, suspicious signals, potential spam |

## Domain Intelligence Signals

The API analyzes multiple signals for each result:

- **WHOIS data**: Domain age, registration length, registrar reputation
- **DNS/Infrastructure**: IP address, ASN, nameserver analysis
- **TLD risk**: Categorization of top-level domains by risk level
- **PageRank**: Open PageRank authority score (0-10)
- **Publisher database**: Known trusted publishers and UGC platforms

## Rate Limits

Rate limits are based on your subscription plan. Contact support for details on higher rate limits.
