# Intelligent Search API 

Intelligent Search API for AI Applications. Wraps search providers (Serper) and adds an intelligence layer with domain trust signals, AI-powered content classification, and source tiering.

## Why Search?

When LLMs use search tools, they receive raw results with no way to distinguish between authoritative sources and SEO spam. Enriches each result with:

- **Domain Intelligence**: WHOIS data, domain age, registration patterns, DNS/infrastructure signals
- **Authority Scores**: Open PageRank integration for domain authority
- **AI Classification**: Content type, quality estimates, affiliate/AI-generated probability
- **Source Tiering**: Simple 1-3 tier system for quick filtering decisions
- **Warning Flags**: Alerts for suspicious patterns (new domains, high-risk TLDs, keyword stuffing)

## Quick Start

### Prerequisites

- Python 3.11+
- Redis (optional, falls back to in-memory cache)
- AWS credentials (for Bedrock AI classification)

### Installation

```bash
# Clone the repository
git clone <repo-url>
cd search-engine

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment template
cp .env.example .env
```

### Configuration

Edit `.env` with your credentials:

```bash
# Required
SERPER_API_KEY=your_serper_api_key_here

# AWS Bedrock for AI classification (uses default credential chain if not set)
AWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_REGION=us-east-1

# Redis (optional - falls back to in-memory cache)
REDIS_URL=redis://localhost:6379

# Open PageRank API (optional, free tier: 100k lookups/month)
# Get key at: https://www.domcop.com/openpagerank/
OPEN_PAGERANK_API_KEY=your_openpagerank_key
```

### Redis SSH Tunnel Setup

1. Place the `redis.pem` key file in your SSH directory:
   ```bash
   cp redis.pem ~/.ssh/redis.pem
   chmod 600 ~/.ssh/redis.pem
   ```

2. Add the following to `~/.ssh/config`:
   ```
   Host my-redis
     HostName 3.87.133.241
     User ec2-user
     IdentityFile ~/.ssh/redis.pem
     LocalForward 6379 localhost:6379
   ```

### Running the API

```bash
# Start Redis SSH tunnel (in a separate terminal)
ssh -N my-redis

# Development
uvicorn api:app --reload --host 0.0.0.0 --port 8000

# Production
uvicorn api:app --host 0.0.0.0 --port 8000 --workers 4
```

## API Endpoints

### `POST /search`

Main search endpoint. Returns enriched search results.

**Request:**
```json
{
  "query": "best project management software 2025",
  "num_results": 10
}
```

**Response:**
```json
{
  "query": "best project management software 2025",
  "results": [
    {
      "title": "Best Project Management Software 2025 | TechRadar",
      "url": "https://techradar.com/best/project-management-software",
      "snippet": "We've tested and reviewed dozens of project management tools...",
      "position": 1,
      "my-service": {
        "tier": 1,
        "trust_score": 85,
        "domain": {
          "name": "techradar.com",
          "tld": ".com",
          "tld_risk": "normal",
          "age_years": 18.5,
          "authority_score": 7.2,
          "is_known_publisher": true,
          "is_ugc_platform": false,
          "whois": {
            "age_days": 6752,
            "registration_years": 5.0,
            "registrar": "MarkMonitor Inc.",
            "registrar_risk": "trusted"
          },
          "dns": {
            "ip_address": "151.101.1.132",
            "asn": "AS54113",
            "asn_risk": "trusted",
            "nameservers": ["ns1.example.com"]
          }
        },
        "classification": {
          "content_type": "comparison",
          "intent": "commercial",
          "affiliate_probability": 0.6,
          "ai_generated_probability": 0.1,
          "quality_estimate": "high"
        },
        "warnings": []
      }
    }
  ],
  "meta": {
    "enrichment_level": "standard",
    "processing_time_ms": 450,
    "results_count": 10,
    "ai_classifications": 8,
    "signals_pending": 0
  }
}
```

### `GET /health`

Health check endpoint.

```json
{
  "status": "healthy",
  "service": "my-service",
  "redis_connected": true
}
```

### Cache Management

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/cache/stats` | GET | Cache statistics and pending lookups |
| `/cache/domains` | GET | List all cached domains |
| `/cache/domain/{domain}` | GET | Get cached data for a specific domain |
| `/cache/domain/{domain}` | DELETE | Clear cache for a specific domain |

## Source Tiering

| Tier | Trust Score | Description | Examples |
|------|-------------|-------------|----------|
| **1** | 70-100 | High-trust, authoritative | Major news, .gov, .edu, official docs |
| **2** | 40-69 | Generally reliable | Mid-authority blogs, corporate sites |
| **3** | 0-39 | Low trust, use caution | New domains, spam patterns, thin content |

## Warning Flags

Results may include these warnings:

| Warning | Description |
|---------|-------------|
| `new_domain` | Domain less than 90 days old |
| `young_domain` | Domain less than 1 year old |
| `suspicious_tld` | High-risk TLD (.xyz, .top, .pw, etc.) |
| `suspicious_registrar` | Known spam-associated registrar |
| `short_registration` | Domain registered for 1 year or less |
| `expiring_soon` | Domain expires within 90 days |
| `sparse_whois` | Missing key WHOIS fields |
| `suspicious_hosting` | Known problematic ASN |
| `suspicious_nameserver` | Free/suspicious DNS provider |
| `low_authority` | PageRank below 1.0 |
| `keyword_stuffed_domain` | Domain matches spam patterns |
| `keyword_stuffed_snippet` | Snippet contains spam keywords |
| `likely_ai_generated` | High probability of AI-generated content |
| `likely_affiliate` | High probability of affiliate content |
| `low_quality_content` | AI classified as low quality |
| `signals_pending` | Background WHOIS lookup in progress |

## Architecture

```
Request → my-service API → Serper (raw SERP)
                    ↓
         ┌─────────────────────┐
         │  Intelligence Layer │
         │  ┌───────┐ ┌─────┐  │
         │  │Domain │ │ AI  │  │
         │  │Intel  │ │Class│  │
         │  │(cache)│ │(LLM)│  │
         │  └───────┘ └─────┘  │
         └─────────────────────┘
                    ↓
         Enriched Response
```

**Domain Intelligence** (cached 1-7 days):
- WHOIS lookup via python-whois
- DNS resolution via dnspython
- ASN lookup via Team Cymru DNS
- PageRank via Open PageRank API

**AI Classification** (cached 1 hour):
- Claude Haiku via AWS Bedrock
- Batch classification for efficiency
- Skipped for known Tier 1 publishers

## Publisher Database

The `data/publishers.json` file contains:

- **tier1_domains**: ~90 known authoritative domains
- **tier1_tld_patterns**: Trusted TLDs (.gov, .edu, .mil)
- **tier3_domain_patterns**: Spam domain regex patterns
- **high_risk_tlds**: TLDs with high spam rates
- **ugc_platforms**: User-generated content sites
- **suspicious_registrars**: Registrars associated with spam
- **trusted_registrars**: Enterprise registrars
- **suspicious_asns**: Known problematic networks
- **trusted_hosting_asns**: Major cloud providers (AWS, GCP, Cloudflare)

## Development

```bash
# Run with auto-reload
uvicorn api:app --reload

# API docs (Swagger UI)
open http://localhost:8000/docs

# Alternative docs (ReDoc)
open http://localhost:8000/redoc
```

## License

MIT
