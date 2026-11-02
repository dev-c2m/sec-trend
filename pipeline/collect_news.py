"""보안 뉴스 수집 진입점.

사용법 (프로젝트 루트에서):
    python -m pipeline.collect_news               # 최근 24시간
    python -m pipeline.collect_news --since 3d    # 최근 3일
    python -m pipeline.collect_news --date 2026-10-31

결과: output/news/YYYY-MM-DD.json
"""
import argparse
import hashlib
import re
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pipeline.collectors.rss import fetch_feed
from pipeline.common import (OUTPUT_DIR, load_toml, now_kst, parse_duration, read_json,
                             today_str, utf8_stdout, write_json)

NEWS_DIR = OUTPUT_DIR / "news"
SEEN_PATH = NEWS_DIR / "seen_ids.json"
SEEN_KEEP_DAYS = 30
SIMILARITY_THRESHOLD = 0.45
# 제목에서 고유명사(회사·제품·조직명)를 1개만 공유할 때, 요약문에서 함께 겹쳐야 하는 고유명사 수
ENTITY_SUMMARY_MIN_SHARED = 3
SUMMARY_ENTITY_CHARS = 400
# 이보다 많은 기사 제목에 나오는 단어는 고유명사로 보지 않는다 (흔한 단어 걸러내기)
ENTITY_MAX_DOCS = 12

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
LATIN_RE = re.compile(r"[a-z0-9][a-z0-9.\-]{2,}")
HANGUL_RE = re.compile(r"[가-힣]{2,}")
STOPWORDS = {
    "the", "and", "for", "with", "from", "that", "this", "are", "was", "has", "have", "into",
    "over", "after", "new", "its", "how", "why", "what", "who", "via", "you", "your", "more",
    "now", "out", "about", "says", "say", "amid", "against", "attack", "attacks", "security",
}
# 고유명사 후보에서 뺄 보안 기사 상투어
GENERIC_EN = {
    "flaw", "flaws", "vulnerability", "vulnerabilities", "breach", "data", "hacker", "hackers",
    "attacker", "attackers", "malware", "ransomware", "exploit", "exploited", "exploits", "critical",
    "patch", "patches", "patched", "warns", "users", "user", "linked", "campaign", "threat", "threats",
    "actors", "million", "report", "reports", "using", "used", "could", "lets", "allows", "than",
    "just", "nearly", "targets", "target", "targeting", "remote", "access", "customer", "customers",
    "chinese", "russian", "north", "korean", "iranian", "state", "group", "gang", "cyber", "cybersecurity",
    "researchers", "found", "discloses", "confirms", "stolen", "steal", "leak", "leaked", "exposed",
}
GENERIC_KO = {
    "개인정보", "해킹", "보안", "취약점", "공격", "가능성", "공식", "공지", "확인", "랜섬웨어",
    "악성코드", "사고", "침해", "피해", "침해사고", "해커", "업데이트", "권고", "제품", "발견", "주의",
    "고객", "기업", "국내", "글로벌", "영향", "여파", "단독", "이용자", "정보", "유출", "사이버",
}
KO_PARTICLES = ("으로", "에서", "에게", "까지", "부터", "의", "도", "은", "는", "이", "가", "을", "를",
                "와", "과", "로", "에")
TRACKING_PARAMS = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "ref", "rss"}


def canonical_url(url: str) -> str:
    """추적 파라미터와 fragment 를 제거한 URL."""
    parts = urlsplit(url.strip())
    query = urlencode([(k, v) for k, v in parse_qsl(parts.query) if k.lower() not in TRACKING_PARAMS])
    path = parts.path.rstrip("/") or "/"
    return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), path, query, ""))


def item_id(url: str) -> str:
    return hashlib.sha1(canonical_url(url).encode("utf-8")).hexdigest()[:16]


def title_tokens(title: str) -> set[str]:
    """제목 유사도 비교용 토큰. 영문은 단어, 한글은 2글자 조각(bigram)."""
    t = title.lower()
    tokens = {w.strip(".-") for w in LATIN_RE.findall(t)} - STOPWORDS
    for word in HANGUL_RE.findall(t):
        tokens.update(word[i:i + 2] for i in range(len(word) - 1))
    return {tok for tok in tokens if tok}


def title_entities(title: str) -> set[str]:
    """고유명사 후보: 4글자 이상 영문 단어, 3글자 이상 한글 단어(조사 제거). 보안 상투어는 뺀다."""
    t = title.lower()
    out = {w.strip(".-") for w in LATIN_RE.findall(t) if len(w.strip(".-")) >= 4}
    out -= STOPWORDS | GENERIC_EN
    for word in HANGUL_RE.findall(t):
        for p in KO_PARTICLES:
            if word.endswith(p) and len(word) - len(p) >= 2:
                word = word[:-len(p)]
                break
        if len(word) >= 3 and word not in GENERIC_KO:
            out.add(word)
    return out


def jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def normalize(entry: dict, source: dict) -> dict:
    text = f"{entry['title']} {entry['summary']}"
    published = entry["published"]
    return {
        "id": item_id(entry["url"]),
        "title": entry["title"],
        "url": canonical_url(entry["url"]),
        "source": source["name"],
        "region": source["region"],
        "lang": source["lang"],
        "kind": source.get("kind", "news"),
        "published": published.isoformat() if published else None,
        "summary": entry["summary"],
        "cve_ids": sorted({c.upper() for c in CVE_RE.findall(text)}),
    }


def cluster(items: list[dict]) -> list[dict]:
    """같은 사건을 다룬 기사를 묶는다. 같은 언어끼리만 비교하고, 언어가 다른 묶음은 /secnews 단계에서 합친다.

    묶는 기준 (둘 중 하나):
    - 제목 유사도(Jaccard) ≥ SIMILARITY_THRESHOLD
    - 흔하지 않은 고유명사(회사·제품명 등)를 제목에서 공유하고, 그 수가 2개 이상이거나 요약문에서도
      고유명사가 ENTITY_SUMMARY_MIN_SHARED 개 이상 겹침
      — 'Chainalysis confirms…' 와 'Chainalysis discloses…' 처럼 제목 표현이 다른 경우를 잡는다.
      제목에 'servers' 같은 단어 하나만 겹치는 다른 기사는 요약문이 달라서 묶이지 않는다.

    대표 기사는 묶음 안에서 가장 먼저 들어온(=입력 순서상 앞선) 기사다.
    """
    entities = {item["id"]: title_entities(item["title"]) for item in items}
    doc_freq: dict[str, int] = {}
    for ents in entities.values():
        for e in ents:
            doc_freq[e] = doc_freq.get(e, 0) + 1

    clusters: list[dict] = []
    for item in items:
        tokens = title_tokens(item["title"])
        ents = {e for e in entities[item["id"]] if doc_freq[e] <= ENTITY_MAX_DOCS}
        sum_ents = title_entities(item["summary"][:SUMMARY_ENTITY_CHARS]) | ents
        best, best_score = None, -1.0
        for c in clusters:
            if c["lang"] != item["lang"]:
                continue
            score = jaccard(tokens, c["_tokens"])
            shared = ents & c["_entities"]
            same_story = score >= SIMILARITY_THRESHOLD or (shared and (
                len(shared) >= 2 or len(sum_ents & c["_sum_entities"]) >= ENTITY_SUMMARY_MIN_SHARED))
            if same_story and score > best_score:
                best, best_score = c, score
        if best is not None:
            best["also"].append({k: item[k] for k in ("source", "title", "url", "published")})
            best["cve_ids"] = sorted(set(best["cve_ids"]) | set(item["cve_ids"]))
            best["_entities"] |= ents
            best["_sum_entities"] |= sum_ents
            continue
        clusters.append({**item, "also": [], "_tokens": tokens, "_entities": set(ents),
                         "_sum_entities": sum_ents})

    for c in clusters:
        for key in ("_tokens", "_entities", "_sum_entities"):
            c.pop(key)
        c["coverage"] = len({c["source"]} | {a["source"] for a in c["also"]})
    return clusters


def fetch_all(sources: list[dict]) -> tuple[list[dict], list[dict]]:
    """모든 소스를 병렬로 가져온다. (항목 목록, 소스별 상태) 를 돌려준다."""
    def work(src):
        try:
            return src, fetch_feed(src["url"]), None
        except Exception as e:  # 한 소스가 실패해도 나머지는 계속 수집한다
            return src, [], f"{type(e).__name__}: {e}"

    items, status = [], []
    with ThreadPoolExecutor(max_workers=8) as pool:
        for src, entries, err in pool.map(work, sources):
            status.append({"name": src["name"], "count": len(entries), "error": err})
            items.extend(normalize(e, src) for e in entries)
    return items, status


def collect(since: timedelta, date: str) -> dict:
    sources = [s for s in load_toml("sources.toml")["sources"] if s.get("enabled", True)]
    raw, status = fetch_all(sources)

    cutoff = now_kst() - since
    in_window = [i for i in raw if i["published"] is None or i["published"] >= cutoff.isoformat()]
    # 같은 URL 중복 제거 후, 화제성 비교를 위해 최신순으로 정렬
    unique = list({i["id"]: i for i in in_window}.values())
    unique.sort(key=lambda i: i["published"] or "", reverse=True)

    clusters = cluster(unique)

    seen = read_json(SEEN_PATH, {})
    for c in clusters:
        # 처음 본 날짜가 오늘이면 새 기사로 본다. 같은 날 여러 번 돌려도(스케줄러 + 수동) 새 기사가 사라지지 않는다.
        first_seen = seen.setdefault(c["id"], date)
        c["new"] = first_seen >= date
    keep_after = (now_kst() - timedelta(days=SEEN_KEEP_DAYS)).strftime("%Y-%m-%d")
    write_json(SEEN_PATH, {k: v for k, v in seen.items() if v >= keep_after})

    clusters.sort(key=lambda c: (c["coverage"], c["published"] or ""), reverse=True)
    return {
        "generated_at": now_kst().isoformat(timespec="seconds"),
        "date": date,
        "window_hours": int(since.total_seconds() // 3600),
        "stats": {
            "fetched": len(raw),
            "in_window": len(unique),
            "clusters": len(clusters),
            "domestic": sum(1 for c in clusters if c["region"] == "국내"),
            "overseas": sum(1 for c in clusters if c["region"] == "해외"),
        },
        "sources": status,
        "items": clusters,
    }


def main(argv=None) -> None:
    utf8_stdout()
    p = argparse.ArgumentParser(description="보안 뉴스 수집")
    p.add_argument("--since", default="24h", help="수집 기간 (예: 24h, 3d, 1w). 기본 24h")
    p.add_argument("--date", default=today_str(), help="저장 파일 날짜 (YYYY-MM-DD). 기본 오늘")
    args = p.parse_args(argv)

    result = collect(parse_duration(args.since), args.date)
    out = NEWS_DIR / f"{args.date}.json"
    write_json(out, result)

    s = result["stats"]
    print(f"[news] 가져온 기사 {s['fetched']} → 기간 내 {s['in_window']} → 묶은 뒤 {s['clusters']}건 "
          f"(국내 {s['domestic']} / 해외 {s['overseas']})")
    for src in result["sources"]:
        mark = f"실패 - {src['error']}" if src["error"] else f"{src['count']}건"
        print(f"  - {src['name']}: {mark}")
    print(f"[news] 저장: {out}")


if __name__ == "__main__":
    main()
