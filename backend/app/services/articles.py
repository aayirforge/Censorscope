"""
backend/app/services/articles.py
Public news article discovery via GDELT 2.0 Doc API.
Retrieves up to 5 related news articles for a domain.
Stores and returns ONLY:
- title
- source
- date
- link
Never stores or fetches article content.
Never claims an article proves a legal block.
Caches queries for 24 hours.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Dict, List

import httpx

logger = logging.getLogger(__name__)

CACHE_TTL_SECONDS = 86400  # 24 hours
_ARTICLE_CACHE: Dict[str, tuple[float, List["ArticleItem"]]] = {}


@dataclass
class ArticleItem:
    title: str
    source: str
    date: str
    link: str


class ArticleService:
    """Service to fetch public news links related to domain blocking."""

    async def get_articles_for_domain(self, domain: str) -> List[ArticleItem]:
        now = time.time()
        if domain in _ARTICLE_CACHE:
            cached_time, items = _ARTICLE_CACHE[domain]
            if now - cached_time < CACHE_TTL_SECONDS:
                return items

        articles: List[ArticleItem] = []
        # GDELT 2.0 Doc API query
        # Terms: domain AND (blocked OR censorship OR ban)
        query = f'"{domain}" (blocked OR censorship OR ban OR court)'
        url = "https://api.gdeltproject.org/api/v2/doc/doc"
        params = {
            "query": query,
            "mode": "artlist",
            "format": "json",
            "maxrecords": "5",
            "sort": "DateDesc",
        }

        try:
            async with httpx.AsyncClient(timeout=6.0) as client:
                resp = await client.get(url, params=params)
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get("articles", [])[:5]:
                        title = item.get("title", "").strip()
                        source = item.get("domain", "").strip() or item.get("sourcecountry", "Web")
                        raw_date = item.get("seendate", "")
                        # Format YYYYMMDDTHHMMSSZ to YYYY-MM-DD
                        formatted_date = raw_date[:8] if len(raw_date) >= 8 else "Recent"
                        if len(formatted_date) == 8:
                            formatted_date = (
                                f"{formatted_date[:4]}-{formatted_date[4:6]}-{formatted_date[6:8]}"
                            )
                        link = item.get("url", "")

                        if title and link:
                            articles.append(
                                ArticleItem(
                                    title=title,
                                    source=source,
                                    date=formatted_date,
                                    link=link,
                                )
                            )
        except Exception as e:
            logger.warning(f"GDELT lookup failed for {domain}: {e}")

        _ARTICLE_CACHE[domain] = (now, articles)
        return articles
