"""RSS 2.0 / Atom 피드 수집기 (stdlib 만 사용)."""
import html
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from email.utils import parsedate_to_datetime

from pipeline.common import KST, http_get

ATOM = "{http://www.w3.org/2005/Atom}"
TAG_RE = re.compile(r"<[^>]+>")
WS_RE = re.compile(r"\s+")
# 워드프레스 피드가 붙이는 상투 문구와 말줄임 표시
BOILERPLATE_RE = re.compile(r"The post .+? appeared first on .+?\.?\s*$|\[\.\.\.\]|\[…\]")


def clean_text(text: str | None, limit: int = 600) -> str:
    """HTML 태그·엔티티를 걷어내고 공백을 정리한다."""
    if not text:
        return ""
    text = html.unescape(TAG_RE.sub(" ", html.unescape(text)))
    text = WS_RE.sub(" ", text).strip()
    text = BOILERPLATE_RE.sub("", text).strip()
    return text if len(text) <= limit else text[:limit].rstrip() + "…"


def parse_date(text: str | None) -> datetime | None:
    """RFC 822, ISO 8601, 'YYYY-MM-DD HH:MM:SS', 'YYYY-MM-DD' 를 처리한다. 시간대가 없으면 KST 로 본다."""
    if not text:
        return None
    text = text.strip()
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", text):
        # 날짜만 있는 피드(보호나라 등)는 그날 끝으로 본다. 그래야 '최근 24시간' 필터에서 빠지지 않는다.
        text += "T23:59:59"
    dt = None
    try:
        dt = parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        pass
    if dt is None:
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=KST)
    return dt.astimezone(KST)


def _text(el, *names) -> str | None:
    for name in names:
        child = el.find(name)
        if child is not None and (child.text or "").strip():
            return child.text.strip()
    return None


def parse_feed(xml_bytes: bytes) -> list[dict]:
    """피드 XML 을 [{title, url, published, summary}] 로 변환한다."""
    root = ET.fromstring(xml_bytes)
    entries = []
    if root.tag == f"{ATOM}feed":
        for e in root.findall(f"{ATOM}entry"):
            link = None
            for l in e.findall(f"{ATOM}link"):
                if l.get("rel", "alternate") == "alternate":
                    link = l.get("href")
                    break
            entries.append({
                "title": clean_text(_text(e, f"{ATOM}title"), 300),
                "url": (link or "").strip(),
                "published": parse_date(_text(e, f"{ATOM}published", f"{ATOM}updated")),
                "summary": clean_text(_text(e, f"{ATOM}summary", f"{ATOM}content")),
            })
    else:
        for item in root.iter("item"):
            entries.append({
                "title": clean_text(_text(item, "title"), 300),
                "url": (_text(item, "link", "guid") or "").strip(),
                "published": parse_date(_text(item, "pubDate", "{http://purl.org/dc/elements/1.1/}date")),
                "summary": clean_text(_text(item, "description", "{http://purl.org/rss/1.0/modules/content/}encoded")),
            })
    return [e for e in entries if e["title"] and e["url"]]


def fetch_feed(url: str) -> list[dict]:
    return parse_feed(http_get(url, timeout=30))
