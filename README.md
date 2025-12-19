# Search Result Context Tool

A personal project to add trust/quality signals to search results. Built this because I got tired of clicking on SEO spam and wanted a way to quickly see which search results are worth reading.

## What It Does

When I search Google, I want to know:
- Is this domain legit or a 2-week-old spam site?
- Is this an established source or content farm?
- For Reddit results: is the author someone with actual community standing?

This tool enriches search results with:
- Domain age (via WHOIS)
- Basic authority signals (PageRank)
- Reddit author karma (for Reddit links)
- Simple trust tier (1-3) so I can quickly skim results

## Current Status

🚧 **Work in progress** - Built for my own use, sharing in case it's useful to others.

## Setup

Requires Python 3.11+

```bash
git clone <repo-url>
cd search-context-tool

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
cp .env.example .env
```

### API Keys Needed

```bash
# .env file
SERPER_API_KEY=your_key          # For search results
OPEN_PAGERANK_API_KEY=your_key   # Optional, free tier works fine

# For Reddit karma lookups
REDDIT_CLIENT_ID=your_client_id
REDDIT_CLIENT_SECRET=your_secret
```

### Running Locally

```bash
uvicorn api:app --reload --port 8000
```

## How Trust Tiers Work

| Tier | What it means |
|------|---------------|
| 1 | Established, authoritative (major publications, .gov, .edu) |
| 2 | Decent - been around a while, some authority |
| 3 | Be cautious - new domain, sketchy TLD, or spam patterns |

## Reddit Integration

For search results from Reddit, the tool fetches the post/comment author's karma via Reddit's API. This gives me quick context on whether I'm reading advice from a throwaway account or an established community member.

**Reddit API usage:**
- Read-only: only calls `/user/{username}/about`
- No data stored beyond current session
- Respects rate limits (100 QPM with OAuth)
- Single-user tool, not a service

## Warnings

The tool flags suspicious patterns:
- `new_domain` - Less than 90 days old
- `young_domain` - Less than 1 year old  
- `suspicious_tld` - Known spam TLDs (.xyz, .top, etc.)
- `low_authority` - PageRank below 1.0

## Data Sources

- WHOIS lookups via python-whois
- DNS/ASN via dnspython
- PageRank via Open PageRank API (free tier)
- Reddit karma via Reddit Data API

## Known Publishers

I maintain a simple list in `data/publishers.json` of:
- Known legit domains (major news, tech sites)
- Spam patterns to flag
- High-risk TLDs

This isn't comprehensive - just patterns I've noticed over time.

## License

MIT - do whatever you want with it

## Notes

This is a personal tool I use locally. Not a hosted service, not monetized, not collecting anyone's data. Just trying to make search results less of a minefield.
