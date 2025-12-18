"""
Verque API - Intelligent Search API for AI Applications

Wraps Serper API and adds intelligence layer with:
- Domain intelligence (WHOIS, age, authority, registrar analysis)
- DNS/Infrastructure signals (IP, ASN, nameservers)
- AI classification (content type, quality, affiliate signals)
- Source tiering (1-3)
"""

import asyncio
import hashlib
import json
import os
import re
import secrets
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import boto3
from botocore.exceptions import ClientError
import dns.resolver
import httpx
import jwt
import redis.asyncio as redis
import stripe
import whois
from dotenv import load_dotenv
from fastapi import FastAPI, Header, HTTPException, Security, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

load_dotenv()

# =============================================================================
# Configuration
# =============================================================================

SERPER_API_KEY = os.getenv("SERPER_API_KEY")

# Bedrock configuration with fallback regions
AWS_REGIONS = ["us-east-1", "us-east-2"]  # Primary and fallback regions
BEDROCK_MODEL_ID = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
BEDROCK_SONNET_MODEL_ID = "anthropic.claude-sonnet-4-5-20250929-v1:0"  # Sonnet 4.5 fallback

# Self-hosted Qwen fallback (OpenAI-compatible endpoint)
QWEN_ENDPOINT = os.getenv("QWEN_ENDPOINT", "http://18.116.189.205:8000")
QWEN_MODEL = os.getenv("QWEN_MODEL", "qwen3-8b")

# Redis configuration
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")

# Open PageRank API (free tier: 100k lookups/month)
OPEN_PAGERANK_API_KEY = os.getenv("OPEN_PAGERANK_API_KEY")

# Stripe configuration
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY")
STRIPE_PUBLISHABLE_KEY = os.getenv("STRIPE_PUBLISHABLE_KEY")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET")
STRIPE_METER_ID = os.getenv("STRIPE_METER_ID")
STRIPE_PRICE_STARTER = os.getenv("STRIPE_PRICE_STARTER")
STRIPE_PRICE_PRO = os.getenv("STRIPE_PRICE_PRO")

# Credits granted for one-time checkout purchases
CHECKOUT_STARTER_CREDITS = float(os.getenv("CHECKOUT_STARTER_CREDITS", "10000"))
CHECKOUT_PRO_CREDITS = float(os.getenv("CHECKOUT_PRO_CREDITS", "50000"))

# Supabase configuration for JWT validation
SUPABASE_JWT_SECRET = os.getenv("SUPABASE_JWT_SECRET")

# Supabase configuration for database operations (recording transactions)
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_KEY")

# Initialize Supabase client
supabase_client = None
if SUPABASE_URL and SUPABASE_SERVICE_KEY:
    from supabase import create_client
    supabase_client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)

# Initialize Stripe
if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

# Cache TTLs (seconds)
WHOIS_CACHE_TTL = 86400 * 7  # 7 days
DNS_CACHE_TTL = 86400  # 1 day
PAGERANK_CACHE_TTL = 86400 * 7  # 7 days
CLASSIFICATION_CACHE_TTL = 3600  # 1 hour

# Background worker thread pool
executor = ThreadPoolExecutor(max_workers=10)

# API Key authentication
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)
API_KEY_PREFIX = "apikey:"  # Redis key prefix for API keys
USER_CREDITS_PREFIX = "credits:"  # Redis key prefix for user credits
CREDIT_LOGS_PREFIX = "creditlogs:"  # Redis key prefix for credit usage logs

# Free credits given to new users on signup (2K free queries)
FREE_SIGNUP_CREDITS = float(os.getenv("FREE_SIGNUP_CREDITS", "2000"))

# Credit costs (configurable via environment variables)
# Classification: 1 credit base (covers first 5 results), +0.2 per additional result
# Verification: free for now (not implemented)
CREDIT_COST_BASE_SEARCH = float(os.getenv("CREDIT_COST_BASE_SEARCH", "1"))
CREDIT_COST_CLASSIFICATION_BASE = float(os.getenv("CREDIT_COST_CLASSIFICATION_BASE", "1"))
CREDIT_COST_CLASSIFICATION_PER_EXTRA = float(os.getenv("CREDIT_COST_CLASSIFICATION_PER_EXTRA", "0.2"))
CREDIT_COST_CLASSIFICATION_INCLUDED = int(os.getenv("CREDIT_COST_CLASSIFICATION_INCLUDED", "5"))
CREDIT_COST_VERIFICATION = float(os.getenv("CREDIT_COST_VERIFICATION", "0"))

# Auto-top-up configuration
STARTER_CREDITS = float(os.getenv("STARTER_CREDITS", "100"))
PRO_CREDITS = float(os.getenv("PRO_CREDITS", "500"))
AUTOTOPUP_PREFIX = "autotopup:"
AUTOTOPUP_COOLDOWN_MINUTES = int(os.getenv("AUTOTOPUP_COOLDOWN_MINUTES", "5"))

app = FastAPI(
    title="Verque API",
    description="Intelligent Search API for AI Applications",
    version="0.2.0",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://localhost:3000",
        "https://verque.app",
        "https://www.verque.app",
        "https://verque-search-web.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Pydantic Models
# =============================================================================

class SearchRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=500)
    num_results: int = Field(default=10, ge=1, le=100)
    ai_classification: bool = Field(default=True, description="Enable AI content classification (+1 credit for first 5 results, +0.2 per additional)")
    verify_claims: bool = Field(default=False, description="Enable claim verification (free, not yet implemented)")


class WhoisInfo(BaseModel):
    age_days: Optional[int] = None
    registration_years: Optional[float] = None
    days_until_expiry: Optional[int] = None
    registrar: Optional[str] = None
    registrar_risk: str = "unknown"  # trusted, normal, suspicious
    has_privacy_protection: bool = False
    is_sparse_whois: bool = False


class DnsInfo(BaseModel):
    ip_address: Optional[str] = None
    asn: Optional[str] = None
    asn_risk: str = "unknown"  # trusted, normal, suspicious
    nameservers: list[str] = []
    nameserver_risk: str = "normal"


class DomainInfo(BaseModel):
    name: str
    tld: str
    tld_risk: str = "normal"  # trusted, normal, high
    age_years: Optional[float] = None
    authority_score: Optional[float] = None  # Open PageRank (0-10)
    is_known_publisher: bool = False
    is_ugc_platform: bool = False
    whois: Optional[WhoisInfo] = None
    dns: Optional[DnsInfo] = None
    signals_pending: bool = False  # True if background lookup in progress


# =============================================================================
# GEO Signal Detection (Heuristic-based)
# =============================================================================

def detect_geo_signals_heuristic(title: str, snippet: str, url: str) -> list[str]:
    """
    Detect GEO (Generative Engine Optimization) signals using pattern matching.
    These are concrete, verifiable signals that don't rely on LLM judgment.

    Returns list of detected signal names.
    """
    signals = []
    text = f"{title} {snippet}".lower()
    title_lower = title.lower()

    # --- definition_front_loading ---
    # Snippets that start with "[Term] is/are..." pattern
    # E.g., "A migraine is a headache that..."
    definition_patterns = [
        r'^[A-Z][a-z\s]{2,30}\s+(is|are|refers to|means|describes)\s+',  # "X is..."
        r'^(The|A|An)\s+[a-z\s]{2,30}\s+(is|are)\s+(a|an|the)\s+',  # "The X is a..."
        r'^[A-Z][a-z]+\s*[-–:]\s+',  # "Term: definition" or "Term - definition"
    ]
    for pattern in definition_patterns:
        if re.match(pattern, snippet):
            signals.append("definition_front_loading")
            break

    # --- list_format_abuse ---
    # Excessive bullet/number indicators in snippet
    list_indicators = [
        r'\d+\.\s+\w',  # "1. Item"
        r'•\s*\w',  # Bullet points
        r'[-–]\s+\w',  # Dash lists
        r'\*\s+\w',  # Asterisk lists
    ]
    list_count = sum(len(re.findall(p, snippet)) for p in list_indicators)
    if list_count >= 3:
        signals.append("list_format_abuse")

    # --- hedge_language_patterns ---
    # Vague authority claims without specifics
    hedge_phrases = [
        r'\baccording to (experts?|research|studies|scientists?|specialists?)\b',
        r'\bstudies (show|suggest|indicate|have shown)\b',
        r'\bresearch (shows|suggests|indicates|has shown)\b',
        r'\bexperts (say|recommend|suggest|agree|believe)\b',
        r'\bit is (widely )?(believed|known|accepted|understood)\b',
        r'\b(many|most|some) (experts?|doctors?|scientists?|researchers?)\b',
        r'\bevidence suggests\b',
        r'\bgenerally (speaking|considered|accepted)\b',
    ]
    hedge_count = sum(1 for p in hedge_phrases if re.search(p, text))
    if hedge_count >= 2:
        signals.append("hedge_language_patterns")
    elif hedge_count == 1:
        # Single hedge is weaker signal, only add if other signals present
        pass  # Will be handled by LLM

    # --- conversational_mimicry ---
    # Fake conversational/friendly tone markers
    conversational_patterns = [
        r"\b(let's|let us) (dive|explore|take a look|discuss|break down)\b",
        r"\b(you might|you may|you'll|you're probably) (wonder|ask|think|want)\b",
        r"\bin this (article|guide|post),? (we'll|we will|you'll|you will)\b",
        r"\b(here's|here is) (everything|what|all) you need to know\b",
        r"\b(ready to|want to|looking to) (learn|discover|find out|understand)\b",
        r"\bever wondered?\b",
        r"\bthe (short|quick|simple) answer is\b",
        r"\b(spoiler alert|tldr|tl;dr)\b",
    ]
    conv_count = sum(1 for p in conversational_patterns if re.search(p, text))
    if conv_count >= 1:
        signals.append("conversational_mimicry")

    # --- authority_mimicry ---
    # Grandiose claims in title without substance
    authority_patterns = [
        r'\b(ultimate|complete|definitive|comprehensive) guide\b',
        r'\beverything you need to know\b',
        r'\b(the )?(only|best|top|#1|number one) (guide|resource|source)\b',
        r'\b\d{4}\s*(edition|update|guide)\b',  # "2025 Guide"
        r'\bexpert (tips|advice|guide|secrets)\b',
        r'\b(proven|guaranteed|secret|insider)\b',
        r'\bmust[- ]read\b',
    ]
    authority_count = sum(1 for p in authority_patterns if re.search(p, title_lower))
    if authority_count >= 1:
        signals.append("authority_mimicry")

    # --- keyword_stuffing ---
    # Same significant word repeated too many times
    words = re.findall(r'\b[a-z]{4,}\b', text)
    if words:
        word_freq = {}
        for w in words:
            if w not in {'this', 'that', 'with', 'from', 'have', 'will', 'your', 'about', 'more', 'their', 'which', 'when', 'what', 'been', 'were', 'they', 'them', 'some', 'could', 'would', 'there', 'into', 'also'}:
                word_freq[w] = word_freq.get(w, 0) + 1
        max_freq = max(word_freq.values()) if word_freq else 0
        total_words = len(words)
        # If a word appears more than 4 times or >15% of content
        if max_freq >= 5 or (total_words > 20 and max_freq / total_words > 0.15):
            signals.append("keyword_stuffing")

    # --- qa_format_overuse ---
    # Question patterns in snippet (especially "What is X?" style)
    qa_patterns = [
        r'\?["\']?\s+[A-Z]',  # Question followed by answer
        r'^(what|how|why|when|where|who|which|can|do|does|is|are)\s+',  # Starts with question word
        r'\b(faq|frequently asked|common questions)\b',
    ]
    qa_count = sum(1 for p in qa_patterns if re.search(p, text, re.IGNORECASE))
    if qa_count >= 2:
        signals.append("qa_format_overuse")

    return signals


class Classification(BaseModel):
    content_type: str = "unknown"
    intent: str = "unknown"
    affiliate_probability: float = 0.0
    ai_generated_probability: float = 0.0
    quality_estimate: str = "medium"
    # GEO (Generative Engine Optimization) detection
    # Signals: definition_front_loading, list_format_abuse, hedge_language_patterns,
    #          conversational_mimicry, authority_mimicry, keyword_stuffing,
    #          qa_format_overuse, excessive_schema_markup, citation_bait
    geo_optimization_probability: float = 0.0
    geo_signals: list[str] = []  # Detected GEO tactics


class VerqueMetadata(BaseModel):
    tier: int
    trust_score: int
    classification: Classification
    warnings: list[str] = []


class EnrichedResult(BaseModel):
    title: str
    url: str
    snippet: str
    position: int
    verque: VerqueMetadata


class CreditUsage(BaseModel):
    credits_used: float
    breakdown: dict  # e.g., {"base": 1, "classification": 5, "verification": 0}


class CreditUsageLog(BaseModel):
    timestamp: str  # ISO format
    query: str
    num_results: int
    ai_classification: bool
    verify_claims: bool
    credits_used: float
    response_time_ms: int
    api_key_prefix: Optional[str] = None  # Track which API key was used


class SearchResponse(BaseModel):
    query: str
    results: list[EnrichedResult]
    credits: CreditUsage
    meta: dict


# =============================================================================
# Redis Cache Layer
# =============================================================================

class RedisCache:
    """Redis cache with fallback to in-memory if Redis unavailable."""

    def __init__(self):
        self._redis: Optional[redis.Redis] = None
        self._fallback: dict[str, tuple[any, float]] = {}
        self._connected = False

    async def connect(self):
        try:
            self._redis = redis.from_url(REDIS_URL, decode_responses=True)
            await self._redis.ping()
            self._connected = True
            print(f"Connected to Redis at {REDIS_URL}")
        except Exception as e:
            print(f"Redis connection failed, using in-memory fallback: {e}")
            self._connected = False

    async def get(self, key: str) -> Optional[str]:
        if self._connected and self._redis:
            try:
                return await self._redis.get(key)
            except Exception:
                pass

        # Fallback
        if key in self._fallback:
            value, expires_at = self._fallback[key]
            if time.time() < expires_at:
                return value
            del self._fallback[key]
        return None

    async def set(self, key: str, value: str, ttl: int = 3600):
        if self._connected and self._redis:
            try:
                await self._redis.setex(key, ttl, value)
                return
            except Exception:
                pass

        # Fallback
        self._fallback[key] = (value, time.time() + ttl)

    async def get_json(self, key: str) -> Optional[dict]:
        data = await self.get(key)
        if data:
            try:
                return json.loads(data)
            except json.JSONDecodeError:
                pass
        return None

    async def set_json(self, key: str, value: dict, ttl: int = 3600):
        await self.set(key, json.dumps(value), ttl)

    async def exists(self, key: str) -> bool:
        if self._connected and self._redis:
            try:
                return await self._redis.exists(key) > 0
            except Exception:
                pass
        return key in self._fallback

    async def delete(self, key: str) -> bool:
        if self._connected and self._redis:
            try:
                return await self._redis.delete(key) > 0
            except Exception:
                pass
        if key in self._fallback:
            del self._fallback[key]
            return True
        return False

    async def close(self):
        if self._redis:
            await self._redis.close()


# Global cache instance
cache = RedisCache()


# =============================================================================
# API Key Authentication
# =============================================================================

async def validate_api_key(api_key: str = Security(API_KEY_HEADER)) -> dict:
    """
    Validate API key from X-API-Key header.
    Returns the user data associated with the key, including api_key_prefix.
    """
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Include 'X-API-Key' header.",
        )

    # Look up the key in Redis
    key_data = await cache.get_json(f"{API_KEY_PREFIX}{api_key}")

    if not key_data:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key.",
        )

    # Add api_key_prefix for logging/tracking purposes
    key_data["api_key_prefix"] = api_key[:15] + "..."

    return key_data


async def validate_supabase_jwt(
    user_id: str,
    authorization: str = Header(None),
) -> dict:
    """
    Validate Supabase JWT from Authorization header and verify user_id matches.
    Used for dashboard endpoints where the frontend authenticates via Supabase.
    """
    if not authorization:
        raise HTTPException(
            status_code=401,
            detail="Missing Authorization header. Include 'Authorization: Bearer <token>'.",
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Invalid Authorization header format. Use 'Bearer <token>'.",
        )

    token = authorization[7:]  # Remove "Bearer " prefix

    if not SUPABASE_JWT_SECRET:
        raise HTTPException(
            status_code=500,
            detail="Supabase JWT secret not configured.",
        )

    try:
        # Decode and validate the JWT
        payload = jwt.decode(
            token,
            SUPABASE_JWT_SECRET,
            algorithms=["HS256"],
            audience="authenticated",
        )

        # Extract user ID from the JWT
        jwt_user_id = payload.get("sub")
        if not jwt_user_id:
            raise HTTPException(
                status_code=401,
                detail="Invalid token: missing user ID.",
            )

        # Verify the requested user_id matches the JWT user_id
        if jwt_user_id != user_id:
            raise HTTPException(
                status_code=403,
                detail="Access denied: user ID mismatch.",
            )

        return {
            "user_id": jwt_user_id,
            "email": payload.get("email"),
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Token has expired.",
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=401,
            detail=f"Invalid token: {str(e)}",
        )


def generate_api_key() -> str:
    """Generate a cryptographically secure API key."""
    # 32 bytes = 256 bits of entropy, URL-safe base64 encoded
    # Prefix with 'vq_' for easy identification
    return f"vq_{secrets.token_urlsafe(32)}"


def calculate_credits_cost(
    num_results: int,
    ai_classification: bool = False,
    verify_claims: bool = False,
) -> float:
    """Calculate total credit cost for a request."""
    cost = CREDIT_COST_BASE_SEARCH

    if ai_classification:
        cost += CREDIT_COST_CLASSIFICATION_BASE
        extra_results = max(0, num_results - CREDIT_COST_CLASSIFICATION_INCLUDED)
        cost += extra_results * CREDIT_COST_CLASSIFICATION_PER_EXTRA

    if verify_claims:
        cost += CREDIT_COST_VERIFICATION

    return cost


async def get_user_credits(user_id: str) -> float:
    """Get current credit balance for a user."""
    credits = await cache.get(f"{USER_CREDITS_PREFIX}{user_id}")
    if credits is None:
        return 0.0
    return float(credits)


async def deduct_credits(user_id: str, amount: float) -> float:
    """
    Deduct credits from user balance. Returns new balance.
    Raises HTTPException if insufficient credits.
    """
    current = await get_user_credits(user_id)

    if current < amount:
        raise HTTPException(
            status_code=402,  # Payment Required
            detail={
                "error": "insufficient_credits",
                "credits_required": amount,
                "credits_available": current,
                "message": f"This request costs {amount} credits but you only have {current}. Please add more credits.",
            },
        )

    new_balance = current - amount
    # Store with no expiry (10 years TTL)
    await cache.set(
        f"{USER_CREDITS_PREFIX}{user_id}",
        str(new_balance),
        ttl=86400 * 365 * 10,
    )
    return new_balance


async def add_credits(user_id: str, amount: float) -> float:
    """Add credits to user balance. Returns new balance."""
    current = await get_user_credits(user_id)
    new_balance = current + amount
    await cache.set(
        f"{USER_CREDITS_PREFIX}{user_id}",
        str(new_balance),
        ttl=86400 * 365 * 10,
    )
    return new_balance


async def set_credits(user_id: str, amount: float) -> float:
    """Set user credit balance to specific amount. Returns new balance."""
    await cache.set(
        f"{USER_CREDITS_PREFIX}{user_id}",
        str(amount),
        ttl=86400 * 365 * 10,
    )
    return amount


async def log_credit_usage(
    user_id: str,
    query: str,
    num_results: int,
    ai_classification: bool,
    verify_claims: bool,
    credits_used: float,
    response_time_ms: int,
    api_key_prefix: Optional[str] = None,
) -> None:
    """Log a credit usage event to Redis for activity tracking."""
    log_entry = CreditUsageLog(
        timestamp=datetime.now(timezone.utc).isoformat(),
        query=query,
        num_results=num_results,
        ai_classification=ai_classification,
        verify_claims=verify_claims,
        credits_used=credits_used,
        response_time_ms=response_time_ms,
        api_key_prefix=api_key_prefix,
    )

    key = f"{CREDIT_LOGS_PREFIX}{user_id}"

    if cache._connected and cache._redis:
        try:
            # Push to list (newest first) and trim to keep last 1000 entries
            await cache._redis.lpush(key, log_entry.model_dump_json())
            await cache._redis.ltrim(key, 0, 999)
        except Exception as e:
            print(f"[CREDIT-LOG] Failed to log usage: {e}")
    else:
        # Fallback: store in memory (limited utility but prevents errors)
        if key not in cache._fallback:
            cache._fallback[key] = ([], time.time())
        logs, _ = cache._fallback[key]
        logs.insert(0, log_entry.model_dump_json())
        cache._fallback[key] = (logs[:1000], time.time())


async def get_credit_logs(user_id: str, limit: int = 100, offset: int = 0) -> list[dict]:
    """Retrieve credit usage logs for a user."""
    key = f"{CREDIT_LOGS_PREFIX}{user_id}"
    logs = []

    if cache._connected and cache._redis:
        try:
            raw_logs = await cache._redis.lrange(key, offset, offset + limit - 1)
            logs = [json.loads(log) for log in raw_logs]
        except Exception as e:
            print(f"[CREDIT-LOG] Failed to retrieve logs: {e}")
    else:
        # Fallback
        if key in cache._fallback:
            all_logs, _ = cache._fallback[key]
            logs = [json.loads(log) for log in all_logs[offset:offset + limit]]

    return logs


# Track domains with pending background lookups
pending_lookups: set[str] = set()


# =============================================================================
# Publisher Database
# =============================================================================

class PublisherDB:
    """Known publisher tier database."""

    def __init__(self):
        self.tier1_domains: set[str] = set()
        self.tier1_tld_patterns: list[str] = []
        self.tier3_domain_patterns: list[re.Pattern] = []
        self.high_risk_tlds: set[str] = set()
        self.ugc_platforms: set[str] = set()
        self.spam_keyword_patterns: list[re.Pattern] = []
        self.suspicious_registrars: set[str] = set()
        self.trusted_registrars: set[str] = set()
        self.suspicious_nameservers: set[str] = set()
        self.suspicious_asns: set[str] = set()
        self.trusted_hosting_asns: set[str] = set()

    def load(self, filepath: str):
        with open(filepath, "r") as f:
            data = json.load(f)

        # Helper to extract values from object entries (new format) or strings (legacy)
        def extract_values(items: list, key: str) -> list:
            result = []
            for item in items:
                if isinstance(item, dict):
                    result.append(item.get(key, ""))
                else:
                    result.append(item)  # Legacy string format
            return result

        self.tier1_domains = set(extract_values(data.get("tier1_domains", []), "domain"))
        self.tier1_tld_patterns = extract_values(data.get("tier1_tld_patterns", []), "pattern")
        self.tier3_domain_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in extract_values(data.get("tier3_domain_patterns", []), "pattern")
        ]
        self.high_risk_tlds = set(extract_values(data.get("high_risk_tlds", []), "tld"))
        self.ugc_platforms = set(extract_values(data.get("ugc_platforms", []), "domain"))
        self.spam_keyword_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in extract_values(data.get("spam_keyword_patterns", []), "pattern")
        ]
        self.suspicious_registrars = set(
            r.lower() for r in extract_values(data.get("suspicious_registrars", []), "name")
        )
        self.trusted_registrars = set(
            r.lower() for r in extract_values(data.get("trusted_registrars", []), "name")
        )
        self.suspicious_nameservers = set(
            ns.lower() for ns in extract_values(data.get("suspicious_nameservers", []), "name")
        )
        self.suspicious_asns = set(extract_values(data.get("suspicious_asns", []), "asn"))
        self.trusted_hosting_asns = set(extract_values(data.get("trusted_hosting_asns", []), "asn"))

    def is_tier1(self, domain: str) -> bool:
        if domain in self.tier1_domains:
            return True
        for pattern in self.tier1_tld_patterns:
            if domain.endswith(pattern):
                return True
        return False

    def matches_tier3_pattern(self, domain: str) -> bool:
        for pattern in self.tier3_domain_patterns:
            if pattern.search(domain):
                return True
        return False

    def is_high_risk_tld(self, domain: str) -> bool:
        for tld in self.high_risk_tlds:
            if domain.endswith(tld):
                return True
        return False

    def is_ugc_platform(self, domain: str) -> bool:
        return domain in self.ugc_platforms

    def has_spam_keywords(self, text: str) -> bool:
        for pattern in self.spam_keyword_patterns:
            if pattern.search(text):
                return True
        return False

    def get_registrar_risk(self, registrar: Optional[str]) -> str:
        if not registrar:
            return "unknown"
        registrar_lower = registrar.lower()
        for trusted in self.trusted_registrars:
            if trusted in registrar_lower:
                return "trusted"
        for suspicious in self.suspicious_registrars:
            if suspicious in registrar_lower:
                return "suspicious"
        return "normal"

    def get_nameserver_risk(self, nameservers: list[str]) -> str:
        for ns in nameservers:
            ns_lower = ns.lower()
            for suspicious in self.suspicious_nameservers:
                if suspicious in ns_lower:
                    return "suspicious"
        return "normal"

    def get_asn_risk(self, asn: Optional[str]) -> str:
        if not asn:
            return "unknown"
        if asn in self.trusted_hosting_asns:
            return "trusted"
        if asn in self.suspicious_asns:
            return "suspicious"
        return "normal"


# Global publisher database
publisher_db = PublisherDB()


# =============================================================================
# Domain Utilities
# =============================================================================

def extract_domain(url: str) -> str:
    """Extract root domain from URL."""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    if domain.startswith("www."):
        domain = domain[4:]
    return domain


def get_tld(domain: str) -> str:
    """Extract TLD from domain."""
    parts = domain.rsplit(".", 1)
    if len(parts) > 1:
        return "." + parts[-1]
    return ""


# =============================================================================
# WHOIS Lookup (Background Worker Pattern)
# =============================================================================

def _sync_whois_lookup(domain: str) -> dict:
    """Synchronous WHOIS lookup (runs in thread pool)."""
    try:
        w = whois.whois(domain)

        result = {
            "creation_date": None,
            "expiration_date": None,
            "registrar": None,
            "age_days": None,
            "registration_years": None,
            "days_until_expiry": None,
            "has_privacy_protection": False,
            "is_sparse_whois": False,
        }

        now = datetime.now(timezone.utc)

        # Creation date / age
        if w.creation_date:
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if isinstance(creation, datetime):
                if creation.tzinfo is None:
                    creation = creation.replace(tzinfo=timezone.utc)
                result["creation_date"] = creation.isoformat()
                result["age_days"] = (now - creation).days

        # Expiration date
        if w.expiration_date:
            exp = w.expiration_date
            if isinstance(exp, list):
                exp = exp[0]
            if isinstance(exp, datetime):
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                result["expiration_date"] = exp.isoformat()
                result["days_until_expiry"] = (exp - now).days

                # Calculate registration length
                if result["creation_date"]:
                    creation = datetime.fromisoformat(result["creation_date"])
                    total_days = (exp - creation).days
                    result["registration_years"] = round(total_days / 365.25, 1)

        # Registrar
        if w.registrar:
            result["registrar"] = str(w.registrar)

        # Privacy protection detection
        if w.name:
            name_str = str(w.name).lower() if w.name else ""
            if any(kw in name_str for kw in ["privacy", "protected", "redacted", "proxy", "whoisguard", "domains by proxy"]):
                result["has_privacy_protection"] = True

        # Sparse WHOIS detection (missing key fields)
        sparse_indicators = 0
        if not w.org:
            sparse_indicators += 1
        if not w.name:
            sparse_indicators += 1
        if not w.emails:
            sparse_indicators += 1
        if not w.address:
            sparse_indicators += 1
        result["is_sparse_whois"] = sparse_indicators >= 3

        return result

    except Exception as e:
        return {"error": str(e)}


async def get_whois_data(domain: str) -> Optional[dict]:
    """Get WHOIS data, launching background worker if not cached."""
    cache_key = f"whois:{domain}"

    # Check cache first
    cached = await cache.get_json(cache_key)
    if cached:
        return cached

    # Check if lookup already pending
    if domain in pending_lookups:
        return None  # Signal that lookup is in progress

    # Launch background worker
    pending_lookups.add(domain)

    async def background_lookup():
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(executor, _sync_whois_lookup, domain)
            await cache.set_json(cache_key, result, WHOIS_CACHE_TTL)
        finally:
            pending_lookups.discard(domain)

    asyncio.create_task(background_lookup())
    return None  # Data not available yet


# =============================================================================
# DNS / Infrastructure Lookup
# =============================================================================

def _sync_dns_lookup(domain: str) -> dict:
    """Synchronous DNS lookup (runs in thread pool)."""
    result = {
        "ip_address": None,
        "nameservers": [],
    }

    try:
        # Get A record (IP address)
        answers = dns.resolver.resolve(domain, "A")
        if answers:
            result["ip_address"] = str(answers[0])
    except Exception:
        pass

    try:
        # Get NS records
        answers = dns.resolver.resolve(domain, "NS")
        result["nameservers"] = [str(rdata).rstrip(".") for rdata in answers]
    except Exception:
        pass

    return result


async def get_dns_data(domain: str) -> Optional[dict]:
    """Get DNS data with caching."""
    cache_key = f"dns:{domain}"

    cached = await cache.get_json(cache_key)
    if cached:
        return cached

    # DNS lookups are fast, do them synchronously in thread pool
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(executor, _sync_dns_lookup, domain)

    await cache.set_json(cache_key, result, DNS_CACHE_TTL)
    return result


# =============================================================================
# ASN Lookup (via IP)
# =============================================================================

async def get_asn_for_ip(ip: str) -> Optional[str]:
    """Get ASN for an IP address using Team Cymru DNS lookup."""
    if not ip:
        return None

    cache_key = f"asn:{ip}"
    cached = await cache.get(cache_key)
    if cached:
        return cached

    try:
        # Reverse IP and query Team Cymru
        reversed_ip = ".".join(reversed(ip.split(".")))
        query = f"{reversed_ip}.origin.asn.cymru.com"

        loop = asyncio.get_event_loop()

        def lookup():
            try:
                answers = dns.resolver.resolve(query, "TXT")
                if answers:
                    # Format: "ASN | IP | Country | Registry | Date"
                    txt = str(answers[0]).strip('"')
                    asn = txt.split("|")[0].strip()
                    return f"AS{asn}"
            except Exception:
                pass
            return None

        asn = await loop.run_in_executor(executor, lookup)
        if asn:
            await cache.set(cache_key, asn, DNS_CACHE_TTL)
        return asn

    except Exception:
        return None


# =============================================================================
# Open PageRank API
# =============================================================================

async def get_pagerank(domain: str) -> Optional[float]:
    """Get Open PageRank score for a domain."""
    if not OPEN_PAGERANK_API_KEY:
        return None

    cache_key = f"pagerank:{domain}"
    cached = await cache.get(cache_key)
    if cached:
        return float(cached)

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                "https://openpagerank.com/api/v1.0/getPageRank",
                params={"domains[]": domain},
                headers={"API-OPR": OPEN_PAGERANK_API_KEY},
                timeout=10.0,
            )
            response.raise_for_status()
            data = response.json()

            if data.get("response") and len(data["response"]) > 0:
                rank = data["response"][0].get("page_rank_decimal")
                if rank is not None:
                    await cache.set(cache_key, str(rank), PAGERANK_CACHE_TTL)
                    return float(rank)
    except Exception:
        pass

    return None


# =============================================================================
# Domain Intelligence (Combines All Signals)
# =============================================================================

async def get_domain_info(url: str) -> DomainInfo:
    """Get comprehensive domain intelligence for a URL."""
    domain = extract_domain(url)
    tld = get_tld(domain)

    # Quick checks from publisher DB
    is_known = publisher_db.is_tier1(domain)
    is_ugc = publisher_db.is_ugc_platform(domain)

    # TLD risk
    if publisher_db.is_high_risk_tld(domain):
        tld_risk = "high"
    elif tld in [".gov", ".edu", ".mil"]:
        tld_risk = "trusted"
    else:
        tld_risk = "normal"

    # For known tier 1 publishers, skip expensive lookups
    if is_known:
        return DomainInfo(
            name=domain,
            tld=tld,
            tld_risk=tld_risk,
            is_known_publisher=True,
            is_ugc_platform=is_ugc,
            signals_pending=False,
        )

    # Gather signals concurrently
    whois_task = get_whois_data(domain)
    dns_task = get_dns_data(domain)
    pagerank_task = get_pagerank(domain)

    whois_data, dns_data, pagerank = await asyncio.gather(
        whois_task, dns_task, pagerank_task
    )

    # Process WHOIS data
    whois_info = None
    age_years = None
    signals_pending = False

    if whois_data and "error" not in whois_data:
        age_days = whois_data.get("age_days")
        age_years = round(age_days / 365.25, 1) if age_days else None

        whois_info = WhoisInfo(
            age_days=age_days,
            registration_years=whois_data.get("registration_years"),
            days_until_expiry=whois_data.get("days_until_expiry"),
            registrar=whois_data.get("registrar"),
            registrar_risk=publisher_db.get_registrar_risk(whois_data.get("registrar")),
            has_privacy_protection=whois_data.get("has_privacy_protection", False),
            is_sparse_whois=whois_data.get("is_sparse_whois", False),
        )
    elif whois_data is None:
        # Background lookup in progress
        signals_pending = True

    # Process DNS data
    dns_info = None
    if dns_data:
        ip = dns_data.get("ip_address")
        asn = await get_asn_for_ip(ip) if ip else None

        dns_info = DnsInfo(
            ip_address=ip,
            asn=asn,
            asn_risk=publisher_db.get_asn_risk(asn),
            nameservers=dns_data.get("nameservers", []),
            nameserver_risk=publisher_db.get_nameserver_risk(dns_data.get("nameservers", [])),
        )

    return DomainInfo(
        name=domain,
        tld=tld,
        tld_risk=tld_risk,
        age_years=age_years,
        authority_score=pagerank,
        is_known_publisher=is_known,
        is_ugc_platform=is_ugc,
        whois=whois_info,
        dns=dns_info,
        signals_pending=signals_pending,
    )


# =============================================================================
# AI Classification (Bedrock)
# =============================================================================

# Cached Bedrock clients per region
_bedrock_clients: dict[str, any] = {}


def get_bedrock_client(region: str = None):
    """Get boto3 Bedrock runtime client for specified region."""
    if region is None:
        region = AWS_REGIONS[0]
    if region not in _bedrock_clients:
        _bedrock_clients[region] = boto3.client(
            "bedrock-runtime",
            region_name=region,
        )
    return _bedrock_clients[region]


async def call_qwen_classification(prompt: str) -> str:
    """Call Qwen via OpenAI-compatible API for classification."""
    if not QWEN_ENDPOINT:
        raise ValueError("QWEN_ENDPOINT not configured")

    # Add /no_think suffix for faster, direct responses
    full_prompt = prompt + " /no_think"

    payload = {
        "model": QWEN_MODEL,
        "messages": [{"role": "user", "content": full_prompt}],
        "max_tokens": 2000,
        "temperature": 0.1,
    }

    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(
            f"{QWEN_ENDPOINT}/v1/chat/completions",
            headers={"Content-Type": "application/json"},
            json=payload,
        )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]


async def call_bedrock_classification(prompt: str, region: str, model_id: str) -> str:
    """Call Bedrock for classification with specified region and model."""
    loop = asyncio.get_event_loop()
    client = get_bedrock_client(region)

    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 2000,
        "messages": [{"role": "user", "content": prompt}]
    })

    response = await loop.run_in_executor(
        None,
        lambda: client.invoke_model(
            modelId=model_id,
            body=body,
            contentType="application/json",
            accept="application/json",
        )
    )

    response_body = json.loads(response["body"].read())
    return response_body.get("content", [{}])[0].get("text", "[]")


async def call_classification_with_fallback(prompt: str) -> str:
    """
    Call classification API with fallback chain:
    1. Haiku us-east-1
    2. Haiku us-east-2
    3. Sonnet 4.5 us-east-1
    4. Sonnet 4.5 us-east-2
    5. Qwen3-8b (self-hosted, last resort)
    """
    fallback_chain = [
        ("bedrock", AWS_REGIONS[0], BEDROCK_MODEL_ID, "Haiku us-east-1"),
        ("bedrock", AWS_REGIONS[1], BEDROCK_MODEL_ID, "Haiku us-east-2"),
        ("bedrock", AWS_REGIONS[0], BEDROCK_SONNET_MODEL_ID, "Sonnet us-east-1"),
        ("bedrock", AWS_REGIONS[1], BEDROCK_SONNET_MODEL_ID, "Sonnet us-east-2"),
        ("qwen", None, None, "Qwen3-8b"),
    ]

    last_error = None
    for provider_type, region, model_id, provider_name in fallback_chain:
        try:
            if provider_type == "bedrock":
                result = await call_bedrock_classification(prompt, region, model_id)
                print(f"Classification succeeded with {provider_name}")
                return result
            elif provider_type == "qwen":
                result = await call_qwen_classification(prompt)
                print(f"Classification succeeded with {provider_name}")
                return result
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("ThrottlingException", "ServiceUnavailableException", "ModelStreamErrorException"):
                print(f"Classification throttled on {provider_name}: {error_code}, trying next...")
                last_error = e
                continue
            else:
                # Non-throttling error, still try fallback
                print(f"Classification error on {provider_name}: {error_code}, trying next...")
                last_error = e
                continue
        except httpx.HTTPStatusError as e:
            if e.response.status_code in (429, 503):
                print(f"Classification throttled on {provider_name}: HTTP {e.response.status_code}, trying next...")
            else:
                print(f"Classification error on {provider_name}: HTTP {e.response.status_code}, trying next...")
            last_error = e
            continue
        except Exception as e:
            print(f"Classification error on {provider_name}: {type(e).__name__}: {e}, trying next...")
            last_error = e
            continue

    # All providers failed
    raise RuntimeError(f"All classification providers failed. Last error: {last_error}")


async def classify_results_batch(results: list[dict]) -> list[Classification]:
    """Classify search results using Bedrock Claude Haiku."""
    if not results:
        return []

    # Check cache first
    classifications = []
    uncached_indices = []

    for i, result in enumerate(results):
        url = result.get("link") or result.get("url", "")
        cache_key = f"classify:{hashlib.md5(url.encode()).hexdigest()}"
        cached = await cache.get_json(cache_key)
        if cached:
            classifications.append(Classification(**cached))
        else:
            classifications.append(None)
            uncached_indices.append(i)

    if not uncached_indices:
        return classifications

    # Prepare batch for classification
    items_to_classify = []
    for i in uncached_indices:
        result = results[i]
        items_to_classify.append({
            "index": i,
            "title": result.get("title", ""),
            "snippet": result.get("snippet", ""),
            "url": result.get("link") or result.get("url", ""),
        })

    # Build prompt - GEO signals are now primarily detected via heuristics,
    # LLM focuses on harder-to-detect signals and overall probability
    prompt = """Analyze these search results and classify each one. For each result, provide:
- content_type: article, product_page, forum_post, news, documentation, listicle, comparison, tutorial, homepage, other
- intent: informational, commercial, navigational, transactional
- affiliate_probability: 0.0-1.0 (likelihood this is affiliate/sponsored content)
- ai_generated_probability: 0.0-1.0 (likelihood content is AI-generated based on patterns like: formulaic structure, lack of specific examples, generic phrasing, no personal voice)
- quality_estimate: high, medium, low
- geo_optimization_probability: 0.0-1.0 (likelihood content is specifically optimized for AI citation/extraction rather than human readers)
  IMPORTANT: Do NOT flag legitimate educational/medical content as GEO-optimized just because it's clearly written.
  GEO optimization means ARTIFICIAL structuring for LLM extraction - not naturally clear writing.
  Signs of TRUE GEO optimization: content feels written FOR machines, unnatural question-answer formatting,
  excessive "what is X" sections, content that prioritizes extractability over readability.
- geo_signals: array of detected GEO tactics from this list ONLY (be conservative, empty array if unsure):
  - "excessive_schema_markup" (snippet shows structured data like ratings, prices, dates crammed together)
  - "citation_bait" (vague authority appeals: "experts say", "studies show" WITHOUT naming specific sources/studies)
  - "synthetic_comprehensiveness" (artificially covers every possible angle in a formulaic way, feels like SEO checklist)

Return JSON array with one object per result in the same order. Be conservative with geo_signals - only flag clear manipulation.

Results to classify:
"""
    for item in items_to_classify:
        prompt += f"\n---\nTitle: {item['title']}\nURL: {item['url']}\nSnippet: {item['snippet']}\n"

    prompt += "\n\nRespond with ONLY a JSON array, no other text."

    try:
        # Use fallback chain for resilient classification
        content = await call_classification_with_fallback(prompt)

        # Debug: print raw response
        print(f"Classification response: {content[:500]}...")

        # Parse JSON response - handle markdown code blocks
        if content.startswith("```"):
            # Strip markdown code block
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
            content = content.strip()

        parsed = json.loads(content)

        # Map classifications back to original indices
        for j, item in enumerate(items_to_classify):
            original_index = item["index"]

            # Run heuristic GEO detection
            heuristic_signals = detect_geo_signals_heuristic(
                title=item["title"],
                snippet=item["snippet"],
                url=item["url"]
            )

            if j < len(parsed):
                c = parsed[j]
                llm_signals = c.get("geo_signals", [])

                # Combine heuristic + LLM signals (deduplicated)
                combined_signals = list(set(heuristic_signals + llm_signals))

                # Adjust geo_optimization_probability based on heuristic signals
                llm_geo_prob = float(c.get("geo_optimization_probability", 0))

                # If multiple heuristic signals detected, boost probability
                if len(heuristic_signals) >= 3:
                    geo_prob = max(llm_geo_prob, 0.7)  # Strong heuristic evidence
                elif len(heuristic_signals) >= 2:
                    geo_prob = max(llm_geo_prob, 0.5)  # Moderate heuristic evidence
                elif len(heuristic_signals) == 1:
                    geo_prob = max(llm_geo_prob, 0.3)  # Weak heuristic evidence
                else:
                    geo_prob = llm_geo_prob

                classification = Classification(
                    content_type=c.get("content_type", "unknown"),
                    intent=c.get("intent", "unknown"),
                    affiliate_probability=float(c.get("affiliate_probability", 0)),
                    ai_generated_probability=float(c.get("ai_generated_probability", 0)),
                    quality_estimate=c.get("quality_estimate", "medium"),
                    geo_optimization_probability=geo_prob,
                    geo_signals=combined_signals,
                )
            else:
                # LLM didn't return classification, use heuristics only
                geo_prob = 0.3 if len(heuristic_signals) >= 2 else 0.1 if heuristic_signals else 0.0
                classification = Classification(
                    geo_optimization_probability=geo_prob,
                    geo_signals=heuristic_signals,
                )

            classifications[original_index] = classification

            # Cache the classification
            url = results[original_index].get("link") or results[original_index].get("url", "")
            cache_key = f"classify:{hashlib.md5(url.encode()).hexdigest()}"
            await cache.set_json(cache_key, classification.model_dump(), CLASSIFICATION_CACHE_TTL)

    except Exception as e:
        # On error, log and return default classifications
        print(f"Classification error: {type(e).__name__}: {e}")
        for i in uncached_indices:
            if classifications[i] is None:
                classifications[i] = Classification()

    # Fill any remaining None values
    return [c if c else Classification() for c in classifications]


# =============================================================================
# Trust Scoring & Tiering
# =============================================================================

def calculate_trust_score(domain_info: DomainInfo, classification: Classification) -> int:
    """Calculate trust score (0-100) based on all signals."""
    score = 50  # Start at neutral

    # Known publisher boost
    if domain_info.is_known_publisher:
        return 85  # High baseline for known publishers

    # === Domain Age Signals ===
    if domain_info.whois and domain_info.whois.age_days:
        age_days = domain_info.whois.age_days
        if age_days < 90:
            score -= 30
        elif age_days < 365:
            score -= 15
        elif age_days > 365 * 5:
            score += 15
        elif age_days > 365 * 10:
            score += 20

    # === Registration Length ===
    if domain_info.whois and domain_info.whois.registration_years:
        reg_years = domain_info.whois.registration_years
        if reg_years <= 1:
            score -= 10
        elif reg_years >= 5:
            score += 10

    # === Registrar Risk ===
    if domain_info.whois:
        if domain_info.whois.registrar_risk == "trusted":
            score += 15
        elif domain_info.whois.registrar_risk == "suspicious":
            score -= 15

    # === Privacy Protection (minor signal) ===
    if domain_info.whois and domain_info.whois.has_privacy_protection:
        score -= 5  # Slight penalty, not inherently bad

    # === Sparse WHOIS ===
    if domain_info.whois and domain_info.whois.is_sparse_whois:
        score -= 10

    # === TLD Risk ===
    if domain_info.tld_risk == "high":
        score -= 25
    elif domain_info.tld_risk == "trusted":
        score += 20

    # === DNS/Infrastructure ===
    if domain_info.dns:
        if domain_info.dns.asn_risk == "trusted":
            score += 10
        elif domain_info.dns.asn_risk == "suspicious":
            score -= 15

        if domain_info.dns.nameserver_risk == "suspicious":
            score -= 10

    # === Authority Score (PageRank) ===
    if domain_info.authority_score is not None:
        if domain_info.authority_score >= 6:
            score += 20
        elif domain_info.authority_score >= 4:
            score += 10
        elif domain_info.authority_score >= 2:
            score += 5
        elif domain_info.authority_score < 1:
            score -= 10

    # === UGC Platform ===
    if domain_info.is_ugc_platform:
        score -= 5  # Slight penalty, quality varies

    # === Classification Signals ===
    if classification.affiliate_probability > 0.8:
        score -= 20
    elif classification.affiliate_probability > 0.5:
        score -= 10

    if classification.ai_generated_probability > 0.8:
        score -= 25
    elif classification.ai_generated_probability > 0.5:
        score -= 15

    if classification.quality_estimate == "high":
        score += 15
    elif classification.quality_estimate == "low":
        score -= 20

    # === GEO Optimization Signals ===
    if classification.geo_optimization_probability > 0.8:
        score -= 25  # Strong GEO manipulation
    elif classification.geo_optimization_probability > 0.5:
        score -= 15  # Moderate GEO signals

    # Additional penalty for multiple GEO tactics
    if len(classification.geo_signals) >= 3:
        score -= 10  # Coordinated GEO effort

    # Clamp to 0-100
    return max(0, min(100, score))


def determine_tier(trust_score: int, domain_info: DomainInfo) -> int:
    """Determine tier (1-3) based on trust score and domain info."""
    # Override: known tier 1 publishers are always tier 1
    if domain_info.is_known_publisher:
        return 1

    # Override: high-risk TLD + very new domain = tier 3
    if domain_info.tld_risk == "high":
        if domain_info.whois and domain_info.whois.age_days and domain_info.whois.age_days < 180:
            return 3

    # Score-based tiering
    if trust_score >= 70:
        return 1
    elif trust_score >= 40:
        return 2
    else:
        return 3


def generate_warnings(
    domain_info: DomainInfo,
    classification: Classification,
    title: str,
    snippet: str
) -> list[str]:
    """Generate warning flags for a result."""
    warnings = []

    # === Domain Age Warnings ===
    if domain_info.whois and domain_info.whois.age_days:
        if domain_info.whois.age_days < 90:
            warnings.append("new_domain")
        elif domain_info.whois.age_days < 365:
            warnings.append("young_domain")

    # === TLD Warning ===
    if domain_info.tld_risk == "high":
        warnings.append("suspicious_tld")

    # === Registrar Warning ===
    if domain_info.whois and domain_info.whois.registrar_risk == "suspicious":
        warnings.append("suspicious_registrar")

    # === Short Registration ===
    if domain_info.whois and domain_info.whois.registration_years:
        if domain_info.whois.registration_years <= 1:
            warnings.append("short_registration")

    # === Expiring Soon ===
    if domain_info.whois and domain_info.whois.days_until_expiry:
        if domain_info.whois.days_until_expiry < 90:
            warnings.append("expiring_soon")

    # === Sparse WHOIS ===
    if domain_info.whois and domain_info.whois.is_sparse_whois:
        warnings.append("sparse_whois")

    # === DNS/Infrastructure Warnings ===
    if domain_info.dns:
        if domain_info.dns.asn_risk == "suspicious":
            warnings.append("suspicious_hosting")
        if domain_info.dns.nameserver_risk == "suspicious":
            warnings.append("suspicious_nameserver")

    # === Low Authority ===
    if domain_info.authority_score is not None and domain_info.authority_score < 1:
        warnings.append("low_authority")

    # === Keyword Stuffing ===
    if publisher_db.matches_tier3_pattern(domain_info.name):
        warnings.append("keyword_stuffed_domain")

    combined_text = f"{title} {snippet}"
    if publisher_db.has_spam_keywords(combined_text):
        warnings.append("keyword_stuffed_snippet")

    # === Classification Warnings ===
    if classification.ai_generated_probability > 0.7:
        warnings.append("likely_ai_generated")

    if classification.affiliate_probability > 0.8:
        warnings.append("likely_affiliate")

    if classification.quality_estimate == "low":
        warnings.append("low_quality_content")

    # === GEO Optimization Warnings ===
    if classification.geo_optimization_probability > 0.7:
        warnings.append("likely_geo_optimized")

    for signal in classification.geo_signals:
        warnings.append(f"geo_{signal}")

    # === Signals Pending ===
    if domain_info.signals_pending:
        warnings.append("signals_pending")

    return warnings


# =============================================================================
# Serper API Client
# =============================================================================

async def search_serper(query: str, num_results: int = 10) -> dict:
    """Call Serper API to get search results."""
    if not SERPER_API_KEY:
        raise HTTPException(status_code=500, detail="SERPER_API_KEY not configured")

    async with httpx.AsyncClient() as client:
        response = await client.post(
            "https://google.serper.dev/search",
            headers={
                "X-API-KEY": SERPER_API_KEY,
                "Content-Type": "application/json",
            },
            json={
                "q": query,
                "num": num_results,
            },
            timeout=30.0,
        )
        response.raise_for_status()
        return response.json()


# =============================================================================
# API Endpoints
# =============================================================================

@app.on_event("startup")
async def startup():
    """Initialize on startup."""
    # Load publisher database
    db_path = os.path.join(os.path.dirname(__file__), "data", "publishers.json")
    if os.path.exists(db_path):
        publisher_db.load(db_path)
        print(f"Loaded publisher database from {db_path}")

    # Connect to Redis
    await cache.connect()


@app.on_event("shutdown")
async def shutdown():
    """Cleanup on shutdown."""
    await cache.close()


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "verque",
        "redis_connected": cache._connected,
    }


@app.post("/search", response_model=SearchResponse)
async def search(request: SearchRequest, user: dict = Depends(validate_api_key)):
    """
    Main search endpoint. Requires API key authentication.

    Returns enriched search results with domain intelligence,
    AI classification, trust scores, and tiering.
    """
    start_time = time.time()
    timings = {}

    # Get raw results from Serper
    t0 = time.time()
    serper_response = await search_serper(request.query, request.num_results)
    organic_results = serper_response.get("organic", [])
    timings["serper_ms"] = int((time.time() - t0) * 1000)

    if not organic_results:
        # Still charge base search cost even for no results
        credits_used = CREDIT_COST_BASE_SEARCH

        # Deduct credits from user balance
        user_id = user.get("user_id")
        if user_id:
            await deduct_credits(user_id, credits_used)

        stripe_customer_id = user.get("stripe_customer_id")
        if stripe_customer_id:
            await record_stripe_usage(stripe_customer_id, int(credits_used))

        return SearchResponse(
            query=request.query,
            results=[],
            credits=CreditUsage(
                credits_used=credits_used,
                breakdown={"base": CREDIT_COST_BASE_SEARCH, "classification": 0, "verification": 0},
            ),
            meta={
                "enrichment_level": "standard",
                "processing_time_ms": int((time.time() - start_time) * 1000),
                "results_count": 0,
                "timings": timings,
            }
        )

    # Gather domain info for all results concurrently
    t0 = time.time()
    domain_tasks = [get_domain_info(r.get("link", "")) for r in organic_results]
    domain_infos = await asyncio.gather(*domain_tasks)
    timings["domain_intel_ms"] = int((time.time() - t0) * 1000)

    # AI classification (batch) - skip for known tier 1 domains
    t0 = time.time()
    results_to_classify = []
    classify_indices = []
    for i, (result, domain_info) in enumerate(zip(organic_results, domain_infos)):
        if not domain_info.is_known_publisher:
            results_to_classify.append({
                "title": result.get("title", ""),
                "snippet": result.get("snippet", ""),
                "link": result.get("link", ""),
            })
            classify_indices.append(i)

    classifications = [Classification() for _ in organic_results]
    if results_to_classify:
        batch_classifications = await classify_results_batch(results_to_classify)
        for j, idx in enumerate(classify_indices):
            classifications[idx] = batch_classifications[j]
    timings["classification_ms"] = int((time.time() - t0) * 1000)

    # Build enriched results
    enriched_results = []
    signals_pending_count = 0

    for i, result in enumerate(organic_results):
        domain_info = domain_infos[i]
        classification = classifications[i]

        if domain_info.signals_pending:
            signals_pending_count += 1

        trust_score = calculate_trust_score(domain_info, classification)
        tier = determine_tier(trust_score, domain_info)
        warnings = generate_warnings(
            domain_info,
            classification,
            result.get("title", ""),
            result.get("snippet", ""),
        )

        enriched_results.append(EnrichedResult(
            title=result.get("title", ""),
            url=result.get("link", ""),
            snippet=result.get("snippet", ""),
            position=result.get("position", i + 1),
            verque=VerqueMetadata(
                tier=tier,
                trust_score=trust_score,
                classification=classification,
                warnings=warnings,
            )
        ))

    processing_time = int((time.time() - start_time) * 1000)

    # Calculate credits used for this request
    credits_used = calculate_credits_cost(
        num_results=len(enriched_results),
        ai_classification=request.ai_classification,
        verify_claims=request.verify_claims,
    )

    # Deduct credits from user balance
    user_id = user.get("user_id")
    if user_id:
        await deduct_credits(user_id, credits_used)
        # Log credit usage for activity tracking
        await log_credit_usage(
            user_id=user_id,
            query=request.query,
            num_results=len(enriched_results),
            ai_classification=request.ai_classification,
            verify_claims=request.verify_claims,
            credits_used=credits_used,
            response_time_ms=processing_time,
            api_key_prefix=user.get("api_key_prefix"),
        )

    # Record usage in Stripe if customer has stripe_customer_id
    stripe_customer_id = user.get("stripe_customer_id")
    stripe_recorded = False
    if stripe_customer_id:
        stripe_recorded = await record_stripe_usage(stripe_customer_id, int(credits_used))

        # Trigger background auto-top-up check (non-blocking)
        async def lookup_and_check_topup():
            try:
                customer = stripe.Customer.retrieve(stripe_customer_id)
                if customer.email:
                    await check_autotopup_background(customer.email)
            except Exception as e:
                print(f"[AUTO-TOPUP-BG] Lookup error: {e}")

        asyncio.create_task(lookup_and_check_topup())

    # Log request
    print(f"[SEARCH] query=\"{request.query}\" results={len(enriched_results)} "
          f"credits={credits_used} stripe_recorded={stripe_recorded} "
          f"total={processing_time}ms serper={timings['serper_ms']}ms "
          f"domain={timings['domain_intel_ms']}ms classify={timings['classification_ms']}ms")

    # Build credits breakdown
    if request.ai_classification:
        extra_results = max(0, len(enriched_results) - CREDIT_COST_CLASSIFICATION_INCLUDED)
        classification_cost = CREDIT_COST_CLASSIFICATION_BASE + (extra_results * CREDIT_COST_CLASSIFICATION_PER_EXTRA)
    else:
        classification_cost = 0
    verification_cost = CREDIT_COST_VERIFICATION if request.verify_claims else 0

    return SearchResponse(
        query=request.query,
        results=enriched_results,
        credits=CreditUsage(
            credits_used=credits_used,
            breakdown={
                "base": CREDIT_COST_BASE_SEARCH,
                "classification": classification_cost,
                "verification": verification_cost,
            },
        ),
        meta={
            "enrichment_level": "standard",
            "processing_time_ms": processing_time,
            "results_count": len(enriched_results),
            "ai_classifications": len(results_to_classify),
            "signals_pending": signals_pending_count,
            "timings": timings,
        }
    )


# =============================================================================
# Cache Inspection Endpoints
# =============================================================================

@app.get("/cache/stats")
async def cache_stats():
    """Get cache statistics."""
    stats = {
        "redis_connected": cache._connected,
        "pending_whois_lookups": list(pending_lookups),
    }

    if cache._connected and cache._redis:
        try:
            info = await cache._redis.info("keyspace")
            stats["redis_info"] = info

            # Count keys by prefix
            whois_keys = []
            dns_keys = []
            pagerank_keys = []
            classify_keys = []

            async for key in cache._redis.scan_iter(match="whois:*", count=100):
                whois_keys.append(key)
            async for key in cache._redis.scan_iter(match="dns:*", count=100):
                dns_keys.append(key)
            async for key in cache._redis.scan_iter(match="pagerank:*", count=100):
                pagerank_keys.append(key)
            async for key in cache._redis.scan_iter(match="classify:*", count=100):
                classify_keys.append(key)

            stats["cached_counts"] = {
                "whois": len(whois_keys),
                "dns": len(dns_keys),
                "pagerank": len(pagerank_keys),
                "classifications": len(classify_keys),
            }
        except Exception as e:
            stats["error"] = str(e)
    else:
        # In-memory fallback stats
        stats["fallback_cache_size"] = len(cache._fallback)

    return stats


@app.get("/cache/domains")
async def cache_list_domains():
    """List all cached domains with their data types."""
    domains = {}

    if cache._connected and cache._redis:
        try:
            async for key in cache._redis.scan_iter(match="whois:*"):
                domain = key.replace("whois:", "")
                if domain not in domains:
                    domains[domain] = []
                domains[domain].append("whois")

            async for key in cache._redis.scan_iter(match="dns:*"):
                domain = key.replace("dns:", "")
                if domain not in domains:
                    domains[domain] = []
                domains[domain].append("dns")

            async for key in cache._redis.scan_iter(match="pagerank:*"):
                domain = key.replace("pagerank:", "")
                if domain not in domains:
                    domains[domain] = []
                domains[domain].append("pagerank")

        except Exception as e:
            return {"error": str(e)}
    else:
        # In-memory fallback
        for key in cache._fallback.keys():
            if key.startswith("whois:"):
                domain = key.replace("whois:", "")
                if domain not in domains:
                    domains[domain] = []
                domains[domain].append("whois")
            elif key.startswith("dns:"):
                domain = key.replace("dns:", "")
                if domain not in domains:
                    domains[domain] = []
                domains[domain].append("dns")
            elif key.startswith("pagerank:"):
                domain = key.replace("pagerank:", "")
                if domain not in domains:
                    domains[domain] = []
                domains[domain].append("pagerank")

    return {
        "total_domains": len(domains),
        "domains": domains,
    }


@app.get("/cache/domain/{domain}")
async def cache_lookup_domain(domain: str):
    """Look up all cached data for a specific domain."""
    result = {
        "domain": domain,
        "whois": None,
        "dns": None,
        "pagerank": None,
        "ttl": {},
    }

    # Get WHOIS data
    whois_data = await cache.get_json(f"whois:{domain}")
    if whois_data:
        result["whois"] = whois_data

    # Get DNS data
    dns_data = await cache.get_json(f"dns:{domain}")
    if dns_data:
        result["dns"] = dns_data

    # Get PageRank
    pagerank = await cache.get(f"pagerank:{domain}")
    if pagerank:
        result["pagerank"] = float(pagerank)

    # Get TTLs if Redis connected
    if cache._connected and cache._redis:
        try:
            whois_ttl = await cache._redis.ttl(f"whois:{domain}")
            dns_ttl = await cache._redis.ttl(f"dns:{domain}")
            pagerank_ttl = await cache._redis.ttl(f"pagerank:{domain}")

            result["ttl"] = {
                "whois": whois_ttl if whois_ttl > 0 else None,
                "dns": dns_ttl if dns_ttl > 0 else None,
                "pagerank": pagerank_ttl if pagerank_ttl > 0 else None,
            }
        except Exception:
            pass

    return result


@app.delete("/cache/domain/{domain}")
async def cache_clear_domain(domain: str):
    """Clear all cached data for a specific domain."""
    deleted = []

    if cache._connected and cache._redis:
        try:
            for prefix in ["whois:", "dns:", "pagerank:", "asn:"]:
                key = f"{prefix}{domain}"
                if await cache._redis.delete(key):
                    deleted.append(key)
        except Exception as e:
            return {"error": str(e)}
    else:
        # In-memory fallback
        for prefix in ["whois:", "dns:", "pagerank:", "asn:"]:
            key = f"{prefix}{domain}"
            if key in cache._fallback:
                del cache._fallback[key]
                deleted.append(key)

    return {"deleted": deleted}


# =============================================================================
# API Key Management Endpoints
# =============================================================================

class CreateApiKeyRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Name for this API key")
    user_id: str = Field(..., min_length=1, description="User ID from Supabase")
    stripe_customer_id: Optional[str] = Field(None, description="Stripe customer ID for usage billing")


class ApiKeyResponse(BaseModel):
    key: str
    name: str
    user_id: str
    created_at: str


@app.post("/api-keys", response_model=ApiKeyResponse)
async def create_api_key(request: CreateApiKeyRequest):
    """
    Create a new API key for a user.

    In production, this should verify the Supabase JWT to ensure
    the user_id matches the authenticated user. For now, accepts
    user_id directly.

    Returns the full API key (only shown once - store it securely).
    """
    api_key = generate_api_key()
    created_at = datetime.now(timezone.utc).isoformat()

    key_data = {
        "user_id": request.user_id,
        "name": request.name,
        "created_at": created_at,
        "stripe_customer_id": request.stripe_customer_id,
    }

    # Store in Redis (no expiry - keys are permanent until deleted)
    # Using setex with very long TTL (10 years) since Redis doesn't have "no expire" in this wrapper
    await cache.set(
        f"{API_KEY_PREFIX}{api_key}",
        json.dumps(key_data),
        ttl=86400 * 365 * 10,  # 10 years
    )

    # Also store a reference from user_id to their keys (for listing)
    user_keys_key = f"user_keys:{request.user_id}"
    existing_keys = await cache.get_json(user_keys_key) or []
    existing_keys.append({
        "key_prefix": api_key[:15] + "...",  # Only store prefix for listing
        "key_hash": hashlib.sha256(api_key.encode()).hexdigest(),  # For deletion lookup
        "name": request.name,
        "created_at": created_at,
    })
    await cache.set(user_keys_key, json.dumps(existing_keys), ttl=86400 * 365 * 10)

    return ApiKeyResponse(
        key=api_key,
        name=request.name,
        user_id=request.user_id,
        created_at=created_at,
    )


class ApiKeyListItem(BaseModel):
    key_prefix: str
    name: str
    created_at: str


@app.get("/api-keys/{user_id}")
async def list_api_keys(user_id: str) -> list[ApiKeyListItem]:
    """
    List all API keys for a user (only shows key prefixes, not full keys).

    In production, verify the Supabase JWT to ensure the requester
    owns this user_id.
    """
    user_keys = await cache.get_json(f"user_keys:{user_id}") or []
    return [
        ApiKeyListItem(
            key_prefix=k["key_prefix"],
            name=k["name"],
            created_at=k["created_at"],
        )
        for k in user_keys
    ]


@app.delete("/api-keys/{user_id}/{key_prefix}")
async def delete_api_key(user_id: str, key_prefix: str):
    """
    Delete an API key by its prefix.

    In production, verify the Supabase JWT to ensure the requester
    owns this user_id.
    """
    user_keys_key = f"user_keys:{user_id}"
    user_keys = await cache.get_json(user_keys_key) or []

    # Find the key matching this prefix
    key_to_delete = None
    remaining_keys = []
    for k in user_keys:
        if k["key_prefix"] == key_prefix:
            key_to_delete = k
        else:
            remaining_keys.append(k)

    if not key_to_delete:
        raise HTTPException(status_code=404, detail="API key not found")

    # We need to find and delete the actual key
    # Since we only have the hash, we need to scan (not ideal for large scale)
    # In production, store the full key encrypted or use a different approach
    if cache._connected and cache._redis:
        async for key in cache._redis.scan_iter(match=f"{API_KEY_PREFIX}*"):
            key_data = await cache.get_json(key)
            if key_data and key_data.get("user_id") == user_id:
                actual_key = key.replace(API_KEY_PREFIX, "")
                if hashlib.sha256(actual_key.encode()).hexdigest() == key_to_delete["key_hash"]:
                    await cache.delete(key)
                    break

    # Update user's key list
    await cache.set(user_keys_key, json.dumps(remaining_keys), ttl=86400 * 365 * 10)

    return {"deleted": key_prefix}


@app.delete("/api-keys/{user_id}/by-name/{key_name}")
async def delete_api_key_by_name(user_id: str, key_name: str):
    """
    Delete an API key by its name.

    Useful when you've lost the key value but remember the name you gave it.

    In production, verify the Supabase JWT to ensure the requester
    owns this user_id.
    """
    user_keys_key = f"user_keys:{user_id}"
    user_keys = await cache.get_json(user_keys_key) or []

    # Find the key matching this name
    key_to_delete = None
    remaining_keys = []
    for k in user_keys:
        if k["name"] == key_name:
            key_to_delete = k
        else:
            remaining_keys.append(k)

    if not key_to_delete:
        raise HTTPException(status_code=404, detail=f"API key with name '{key_name}' not found")

    # We need to find and delete the actual key
    # Since we only have the hash, we need to scan (not ideal for large scale)
    # In production, store the full key encrypted or use a different approach
    if cache._connected and cache._redis:
        async for key in cache._redis.scan_iter(match=f"{API_KEY_PREFIX}*"):
            key_data = await cache.get_json(key)
            if key_data and key_data.get("user_id") == user_id:
                actual_key = key.replace(API_KEY_PREFIX, "")
                if hashlib.sha256(actual_key.encode()).hexdigest() == key_to_delete["key_hash"]:
                    await cache.delete(key)
                    break

    # Update user's key list
    await cache.set(user_keys_key, json.dumps(remaining_keys), ttl=86400 * 365 * 10)

    return {"deleted": key_name, "key_prefix": key_to_delete["key_prefix"]}


# =============================================================================
# Stripe Billing Endpoints
# =============================================================================

class CreateCheckoutRequest(BaseModel):
    plan: str = Field(..., description="Plan name: 'free', 'starter', or 'pro'")
    user_email: str = Field(..., description="User's email address")
    user_id: Optional[str] = Field(None, description="Optional user ID from Supabase")
    success_url: str = Field(default="https://verque.app/success?session_id={CHECKOUT_SESSION_ID}")
    cancel_url: str = Field(default="https://verque.app/pricing")


class CheckoutResponse(BaseModel):
    # For paid plans (starter/pro) - redirects to Stripe
    checkout_url: Optional[str] = None
    session_id: Optional[str] = None
    # For free plan - instant activation
    status: Optional[str] = None
    credits_granted: Optional[float] = None


# =============================================================================
# Auto-Top-Up Models
# =============================================================================

class SetupIntentResponse(BaseModel):
    client_secret: str
    setup_intent_id: str


class PaymentMethodInfo(BaseModel):
    id: str
    brand: Optional[str] = None
    last4: Optional[str] = None
    exp_month: Optional[int] = None
    exp_year: Optional[int] = None


class AutoTopUpSettings(BaseModel):
    enabled: bool = False
    threshold: float = Field(default=10.0, ge=0, description="Trigger top-up when balance falls below this")
    package: str = Field(default="starter", description="Package to purchase: 'starter' or 'pro'")
    payment_method: Optional[PaymentMethodInfo] = None
    last_triggered: Optional[str] = None


class ConfigureAutoTopUpRequest(BaseModel):
    email: str = Field(..., description="User's email address")
    payment_method_id: str = Field(..., description="Stripe payment method ID from SetupIntent")
    enabled: bool = Field(default=True)
    threshold: float = Field(default=10.0, ge=0)
    package: str = Field(default="starter", pattern="^(starter|pro)$")


class UpdateAutoTopUpRequest(BaseModel):
    enabled: Optional[bool] = None
    threshold: Optional[float] = Field(default=None, ge=0)
    package: Optional[str] = Field(default=None, pattern="^(starter|pro)$")


class AutoTopUpCheckRequest(BaseModel):
    email: str = Field(..., description="User's email to check")


class AutoTopUpCheckResponse(BaseModel):
    triggered: bool
    previous_balance: Optional[float] = None
    new_balance: Optional[float] = None
    credits_added: Optional[float] = None
    charge_id: Optional[str] = None
    error: Optional[str] = None


@app.post("/billing/create-checkout-session", response_model=CheckoutResponse)
async def create_checkout_session(request: CreateCheckoutRequest):
    """
    Create a Stripe checkout session for subscription, or activate free tier.

    For 'free' plan: Grants free credits immediately, no Stripe redirect.
    For 'starter'/'pro': Returns a checkout URL to redirect user to Stripe.
    """
    valid_plans = ["free", "starter", "pro"]
    if request.plan not in valid_plans:
        raise HTTPException(status_code=400, detail=f"Invalid plan: {request.plan}. Must be one of: {valid_plans}")

    # Handle free tier - no Stripe needed
    if request.plan == "free":
        if not request.user_id:
            raise HTTPException(status_code=400, detail="user_id is required for free plan activation")

        # Check if user already has credits (prevent abuse)
        current_credits = await get_user_credits(request.user_id)
        if current_credits > 0:
            return CheckoutResponse(
                status="already_active",
                credits_granted=0,
            )

        # Grant free signup credits
        await set_credits(request.user_id, FREE_SIGNUP_CREDITS)
        return CheckoutResponse(
            status="activated",
            credits_granted=FREE_SIGNUP_CREDITS,
        )

    # Paid plans require Stripe
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe not configured")

    # Map plan name to price ID
    price_map = {
        "starter": STRIPE_PRICE_STARTER,
        "pro": STRIPE_PRICE_PRO,
    }

    price_id = price_map[request.plan]
    if not price_id:
        raise HTTPException(status_code=500, detail=f"Price ID for plan '{request.plan}' not configured")

    try:
        # Create or retrieve customer
        customers = stripe.Customer.list(email=request.user_email, limit=1)

        if customers.data:
            customer = customers.data[0]
        else:
            customer = stripe.Customer.create(
                email=request.user_email,
                metadata={"verque_user_id": request.user_id or "unknown"}
            )

        # Determine credits to grant based on plan
        credits_to_grant = CHECKOUT_STARTER_CREDITS if request.plan == "starter" else CHECKOUT_PRO_CREDITS

        # Create checkout session with metadata for webhook processing
        session = stripe.checkout.Session.create(
            customer=customer.id,
            mode="payment",
            line_items=[{
                "price": price_id,
                "quantity": 1,
            }],
            success_url=request.success_url,
            cancel_url=request.cancel_url,
            metadata={
                "verque_user_id": request.user_id or "",
                "verque_plan": request.plan,
                "verque_credits": str(int(credits_to_grant)),
            },
        )

        return CheckoutResponse(
            checkout_url=session.url,
            session_id=session.id,
        )

    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/billing/webhook")
async def stripe_webhook(request: Request):
    """
    Handle Stripe webhook events.

    This endpoint receives events from Stripe when payments complete.
    It grants credits to users after successful checkout.
    """
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    # Verify webhook signature if secret is configured
    if STRIPE_WEBHOOK_SECRET:
        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, STRIPE_WEBHOOK_SECRET
            )
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid payload")
        except stripe.error.SignatureVerificationError:
            raise HTTPException(status_code=400, detail="Invalid signature")
    else:
        # For development/testing without webhook secret
        event = json.loads(payload)

    # Handle checkout.session.completed event
    if event["type"] == "checkout.session.completed":
        session = event["data"]["object"]
        metadata = session.get("metadata", {})

        user_id = metadata.get("verque_user_id")
        credits_str = metadata.get("verque_credits")
        plan = metadata.get("verque_plan")

        if user_id and credits_str:
            try:
                credits_to_add = float(credits_str)

                # Get current credits and add new credits
                current_credits = await get_user_credits(user_id)
                new_balance = current_credits + credits_to_add
                await set_credits(user_id, new_balance)

                # Record the transaction in Supabase
                if supabase_client:
                    try:
                        supabase_client.table("billing_transactions").insert({
                            "user_id": user_id,
                            "amount": int(credits_to_add),
                            "transaction_type": "purchase",
                            "description": f"{plan.capitalize()} package - {int(credits_to_add):,} credits",
                        }).execute()
                    except Exception as tx_err:
                        print(f"[WEBHOOK] Failed to record transaction: {tx_err}")

                print(f"[WEBHOOK] Granted {credits_to_add} credits to user {user_id} "
                      f"(plan={plan}, new_balance={new_balance})")
            except Exception as e:
                print(f"[WEBHOOK] Error granting credits: {e}")
                # Don't raise - we don't want Stripe to retry for application errors
        else:
            print(f"[WEBHOOK] Missing user_id or credits in metadata: {metadata}")

    return {"status": "ok"}


async def record_stripe_usage(stripe_customer_id: str, credits_used: int) -> bool:
    """
    Record credit usage in Stripe Meter.
    Call this AFTER each successful API request.
    Returns True if successful, False otherwise.
    """
    if not STRIPE_SECRET_KEY or not STRIPE_METER_ID:
        return False

    try:
        stripe.billing.MeterEvent.create(
            event_name="verque_credits_used",  # Must match meter event name in Stripe
            payload={
                "value": str(credits_used),
                "stripe_customer_id": stripe_customer_id,
            },
            timestamp=int(time.time()),
        )
        return True
    except stripe.error.StripeError as e:
        # Log but don't fail the main request
        print(f"[STRIPE] Failed to record usage: {e}")
        return False


# =============================================================================
# Auto-Top-Up Helper Functions
# =============================================================================

async def get_autotopup_settings(email: str) -> Optional[dict]:
    """Get auto-top-up settings for a user by email."""
    return await cache.get_json(f"{AUTOTOPUP_PREFIX}{email}")


async def save_autotopup_settings(email: str, settings: dict) -> None:
    """Save auto-top-up settings for a user."""
    settings["updated_at"] = datetime.now(timezone.utc).isoformat()
    await cache.set_json(
        f"{AUTOTOPUP_PREFIX}{email}",
        settings,
        ttl=86400 * 365 * 10,
    )


async def get_user_id_from_email(email: str) -> Optional[str]:
    """Look up user_id from Stripe customer metadata."""
    try:
        customers = stripe.Customer.list(email=email, limit=1)
        if customers.data:
            return customers.data[0].metadata.get("verque_user_id")
    except stripe.error.StripeError:
        pass
    return None


async def get_price_amount(price_id: str) -> int:
    """Get the amount in cents for a Stripe price ID."""
    try:
        price = stripe.Price.retrieve(price_id)
        return price.unit_amount
    except stripe.error.StripeError:
        # Fallback defaults
        if price_id == STRIPE_PRICE_STARTER:
            return 999  # $9.99
        return 2999  # $29.99 for pro


async def execute_auto_topup(email: str) -> dict:
    """
    Execute an auto-top-up charge for a user.
    Returns dict with: triggered, previous_balance, new_balance, credits_added, charge_id, error
    """
    settings = await get_autotopup_settings(email)

    if not settings or not settings.get("enabled"):
        return {"triggered": False, "error": "Auto-top-up not enabled"}

    # Check cooldown period
    last_triggered = settings.get("last_triggered")
    if last_triggered:
        last_time = datetime.fromisoformat(last_triggered)
        elapsed_seconds = (datetime.now(timezone.utc) - last_time).total_seconds()
        if elapsed_seconds < AUTOTOPUP_COOLDOWN_MINUTES * 60:
            return {"triggered": False, "error": f"Cooldown period ({AUTOTOPUP_COOLDOWN_MINUTES} min)"}

    # Check lock to prevent duplicate charges
    lock_key = f"autotopup_lock:{email}"
    if await cache.exists(lock_key):
        return {"triggered": False, "error": "Top-up already in progress"}

    # Acquire lock
    await cache.set(lock_key, "1", ttl=60)

    try:
        # Get user_id for credit operations
        user_id = await get_user_id_from_email(email)
        if not user_id:
            return {"triggered": False, "error": "User not found"}

        # Check current balance against threshold
        current_balance = await get_user_credits(user_id)
        threshold = settings.get("threshold", 10.0)

        if current_balance >= threshold:
            return {"triggered": False, "error": f"Balance {current_balance} >= threshold {threshold}"}

        # Determine package and credits
        package = settings.get("package", "starter")
        price_id = STRIPE_PRICE_STARTER if package == "starter" else STRIPE_PRICE_PRO
        credits_to_add = STARTER_CREDITS if package == "starter" else PRO_CREDITS

        payment_method_id = settings.get("payment_method_id")
        customer_id = settings.get("stripe_customer_id")

        if not payment_method_id or not customer_id:
            return {"triggered": False, "error": "No payment method configured"}

        # Get price amount
        amount = await get_price_amount(price_id)

        # Create PaymentIntent and charge immediately
        payment_intent = stripe.PaymentIntent.create(
            amount=amount,
            currency="usd",
            customer=customer_id,
            payment_method=payment_method_id,
            off_session=True,
            confirm=True,
            metadata={
                "type": "auto_topup",
                "package": package,
                "credits": str(credits_to_add),
                "email": email,
            }
        )

        if payment_intent.status == "succeeded":
            # Add credits to user balance
            new_balance = await add_credits(user_id, credits_to_add)

            # Update last_triggered timestamp
            settings["last_triggered"] = datetime.now(timezone.utc).isoformat()
            await save_autotopup_settings(email, settings)

            # Record the transaction in Supabase
            if supabase_client:
                try:
                    supabase_client.table("billing_transactions").insert({
                        "user_id": user_id,
                        "amount": int(credits_to_add),
                        "transaction_type": "auto_topup",
                        "description": f"Auto top-up ({package}) - {int(credits_to_add):,} credits",
                    }).execute()
                except Exception as tx_err:
                    print(f"[AUTO-TOPUP] Failed to record transaction: {tx_err}")

            # Log the transaction
            print(f"[AUTO-TOPUP] {email}: +{credits_to_add} credits ({package}), "
                  f"balance: {current_balance} -> {new_balance}")

            return {
                "triggered": True,
                "previous_balance": current_balance,
                "new_balance": new_balance,
                "credits_added": credits_to_add,
                "charge_id": payment_intent.id,
            }
        else:
            return {"triggered": False, "error": f"Payment status: {payment_intent.status}"}

    except stripe.error.CardError as e:
        return {"triggered": False, "error": f"Card declined: {e.user_message}"}
    except stripe.error.StripeError as e:
        return {"triggered": False, "error": f"Stripe error: {str(e)}"}
    finally:
        # Release lock
        await cache.delete(lock_key)


async def check_autotopup_background(email: str) -> None:
    """
    Non-blocking background task to check and execute auto-top-up.
    Swallows exceptions to avoid affecting the main request.
    """
    try:
        result = await execute_auto_topup(email)
        if result.get("triggered"):
            print(f"[AUTO-TOPUP-BG] Triggered for {email}: +{result.get('credits_added')} credits")
        elif result.get("error") and "Balance" not in result.get("error", ""):
            # Only log actual errors, not "balance above threshold"
            print(f"[AUTO-TOPUP-BG] {email}: {result.get('error')}")
    except Exception as e:
        print(f"[AUTO-TOPUP-BG] Error for {email}: {e}")


@app.get("/billing/customer/{email}")
async def get_customer_info(email: str):
    """
    Get Stripe customer info by email.
    Useful for looking up customer_id to record usage.
    """
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe not configured")

    try:
        customers = stripe.Customer.list(email=email, limit=1)

        if not customers.data:
            raise HTTPException(status_code=404, detail="Customer not found")

        customer = customers.data[0]

        # Get active subscriptions
        subscriptions = stripe.Subscription.list(customer=customer.id, status="active", limit=5)

        return {
            "customer_id": customer.id,
            "email": customer.email,
            "created": customer.created,
            "metadata": customer.metadata,
            "subscriptions": [
                {
                    "id": sub.id,
                    "status": sub.status,
                    "current_period_start": sub.current_period_start,
                    "current_period_end": sub.current_period_end,
                    "plan_id": sub.items.data[0].price.id if sub.items.data else None,
                }
                for sub in subscriptions.data
            ],
        }

    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=str(e))


class RecordUsageRequest(BaseModel):
    stripe_customer_id: str = Field(..., description="Stripe customer ID (cus_xxxxx)")
    credits_used: int = Field(..., ge=1, description="Number of credits to record")


@app.post("/billing/record-usage")
async def record_usage_endpoint(request: RecordUsageRequest):
    """
    Manually record credit usage in Stripe Meter.
    This is primarily for testing - usage is automatically recorded on /search.
    """
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe not configured")

    success = await record_stripe_usage(request.stripe_customer_id, request.credits_used)

    if success:
        return {"status": "recorded", "credits": request.credits_used}
    else:
        raise HTTPException(status_code=500, detail="Failed to record usage in Stripe")


@app.get("/billing/usage/{user_id}")
async def get_usage_summary(user_id: str):
    """
    Get current credit balance for a user.
    Returns credits remaining from Redis.
    """
    credits_balance = await get_user_credits(user_id)

    return {
        "user_id": user_id,
        "credits_balance": credits_balance,
    }


@app.get("/billing/activity")
async def get_activity_logs(
    user: dict = Depends(validate_api_key),
    limit: int = 100,
    offset: int = 0,
):
    """
    Get credit usage activity logs for the authenticated user.
    Returns a list of recent search requests with query, results, credits used, etc.
    """
    user_id = user.get("user_id")
    if not user_id:
        raise HTTPException(status_code=400, detail="User ID not found in API key data")

    logs = await get_credit_logs(user_id, limit=min(limit, 1000), offset=offset)

    return {
        "user_id": user_id,
        "logs": logs,
        "count": len(logs),
        "limit": limit,
        "offset": offset,
    }


# =============================================================================
# Auto-Top-Up Endpoints
# =============================================================================

@app.post("/billing/create-setup-intent", response_model=SetupIntentResponse)
async def create_setup_intent(email: str):
    """
    Create a Stripe SetupIntent for saving a payment method.
    Returns client_secret for the frontend to complete card setup.
    """
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe not configured")

    try:
        # Get or create customer
        customers = stripe.Customer.list(email=email, limit=1)

        if customers.data:
            customer = customers.data[0]
        else:
            customer = stripe.Customer.create(
                email=email,
                metadata={"verque_user_id": "pending"}
            )

        # Create SetupIntent
        setup_intent = stripe.SetupIntent.create(
            customer=customer.id,
            payment_method_types=["card"],
            usage="off_session",
            metadata={
                "purpose": "auto_topup",
                "email": email,
            }
        )

        return SetupIntentResponse(
            client_secret=setup_intent.client_secret,
            setup_intent_id=setup_intent.id,
        )

    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/billing/auto-topup/{email}", response_model=AutoTopUpSettings)
async def get_auto_topup_settings_endpoint(email: str):
    """
    Get current auto-top-up settings for a user.
    Returns enabled status, threshold, package, and payment method info.
    """
    settings = await get_autotopup_settings(email)

    if not settings:
        return AutoTopUpSettings(enabled=False)

    # Fetch payment method details from Stripe if configured
    payment_info = None
    if settings.get("payment_method_id"):
        try:
            pm = stripe.PaymentMethod.retrieve(settings["payment_method_id"])
            if pm.card:
                payment_info = PaymentMethodInfo(
                    id=pm.id,
                    brand=pm.card.brand,
                    last4=pm.card.last4,
                    exp_month=pm.card.exp_month,
                    exp_year=pm.card.exp_year,
                )
        except stripe.error.StripeError:
            pass

    return AutoTopUpSettings(
        enabled=settings.get("enabled", False),
        threshold=settings.get("threshold", 10.0),
        package=settings.get("package", "starter"),
        payment_method=payment_info,
        last_triggered=settings.get("last_triggered"),
    )


@app.post("/billing/auto-topup/configure", response_model=AutoTopUpSettings)
async def configure_auto_topup(request: ConfigureAutoTopUpRequest):
    """
    Configure auto-top-up settings with a payment method.
    Attaches the payment method to the Stripe customer.
    """
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe not configured")

    try:
        # Get customer
        customers = stripe.Customer.list(email=request.email, limit=1)

        if not customers.data:
            raise HTTPException(status_code=404, detail="Customer not found. Please complete a checkout first.")

        customer = customers.data[0]

        # Attach payment method to customer (if not already attached)
        try:
            stripe.PaymentMethod.attach(
                request.payment_method_id,
                customer=customer.id,
            )
        except stripe.error.InvalidRequestError as e:
            if "already been attached" not in str(e):
                raise

        # Set as default payment method
        stripe.Customer.modify(
            customer.id,
            invoice_settings={"default_payment_method": request.payment_method_id},
        )

        # Save settings to Redis
        settings = {
            "enabled": request.enabled,
            "threshold": request.threshold,
            "package": request.package,
            "payment_method_id": request.payment_method_id,
            "stripe_customer_id": customer.id,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        await save_autotopup_settings(request.email, settings)

        # Fetch payment method details for response
        pm = stripe.PaymentMethod.retrieve(request.payment_method_id)
        payment_info = PaymentMethodInfo(
            id=pm.id,
            brand=pm.card.brand if pm.card else None,
            last4=pm.card.last4 if pm.card else None,
            exp_month=pm.card.exp_month if pm.card else None,
            exp_year=pm.card.exp_year if pm.card else None,
        )

        return AutoTopUpSettings(
            enabled=request.enabled,
            threshold=request.threshold,
            package=request.package,
            payment_method=payment_info,
        )

    except stripe.error.StripeError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.patch("/billing/auto-topup/{email}", response_model=AutoTopUpSettings)
async def update_auto_topup_settings_endpoint(email: str, request: UpdateAutoTopUpRequest):
    """
    Update auto-top-up settings (partial update).
    Only provided fields will be updated.
    """
    settings = await get_autotopup_settings(email)

    if not settings:
        raise HTTPException(status_code=404, detail="Auto-top-up not configured for this user")

    # Apply partial updates
    if request.enabled is not None:
        settings["enabled"] = request.enabled
    if request.threshold is not None:
        settings["threshold"] = request.threshold
    if request.package is not None:
        settings["package"] = request.package

    await save_autotopup_settings(email, settings)

    # Fetch payment method details for response
    payment_info = None
    if settings.get("payment_method_id"):
        try:
            pm = stripe.PaymentMethod.retrieve(settings["payment_method_id"])
            if pm.card:
                payment_info = PaymentMethodInfo(
                    id=pm.id,
                    brand=pm.card.brand,
                    last4=pm.card.last4,
                    exp_month=pm.card.exp_month,
                    exp_year=pm.card.exp_year,
                )
        except stripe.error.StripeError:
            pass

    return AutoTopUpSettings(
        enabled=settings.get("enabled", False),
        threshold=settings.get("threshold", 10.0),
        package=settings.get("package", "starter"),
        payment_method=payment_info,
        last_triggered=settings.get("last_triggered"),
    )


@app.post("/billing/auto-topup/check", response_model=AutoTopUpCheckResponse)
async def check_auto_topup_endpoint(request: AutoTopUpCheckRequest):
    """
    Check if auto-top-up should be triggered and execute if needed.
    Can be called manually or as part of background processing.
    """
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="Stripe not configured")

    result = await execute_auto_topup(request.email)

    return AutoTopUpCheckResponse(**result)


# =============================================================================
# Dashboard Endpoints (Supabase JWT Auth)
# =============================================================================

@app.get("/billing/activity/{user_id}")
async def get_activity_logs_by_user(
    user_id: str,
    authorization: str = Header(None),
    limit: int = 100,
    offset: int = 0,
):
    """
    Get credit usage activity logs for a user (dashboard endpoint).
    Requires Supabase JWT authentication.
    """
    await validate_supabase_jwt(user_id, authorization)

    logs = await get_credit_logs(user_id, limit=min(limit, 1000), offset=offset)

    return {
        "user_id": user_id,
        "logs": logs,
        "count": len(logs),
        "limit": limit,
        "offset": offset,
    }


@app.get("/billing/credits/{user_id}")
async def get_credits_by_user(
    user_id: str,
    authorization: str = Header(None),
):
    """
    Get credit balance for a user (dashboard endpoint).
    Requires Supabase JWT authentication.
    """
    await validate_supabase_jwt(user_id, authorization)

    credits_balance = await get_user_credits(user_id)

    return {
        "user_id": user_id,
        "credits_balance": credits_balance,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
