"""NVD CVE API 2.0 수집기.

- API 키가 없으면 30초에 5회까지라 요청 사이에 6.5초 쉰다. 환경변수 NVD_API_KEY 가 있으면 0.7초.
- 발행일 범위는 한 요청에 최대 120일이라 나눠서 요청한다.
- 조회 기간을 하루 단위(UTC)로 맞추고 응답을 cache_ttl 동안 디스크에 캐시한다.
  같은 날 다시 돌리거나 watchlist·구성요소가 같은 조회를 반복하면 요청 없이 바로 돌려준다.
"""
import gzip
import hashlib
import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from pipeline.common import OUTPUT_DIR, http_get_json

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_RANGE = timedelta(days=119)
PAGE_SIZE = 2000
CACHE_DIR = OUTPUT_DIR / "cache" / "nvd"
CACHE_TTL = timedelta(hours=6)


class NvdClient:
    def __init__(self, api_key: str | None = None, fetch=http_get_json, sleep=time.sleep,
                 cache_dir: Path | None = CACHE_DIR, cache_ttl: timedelta = CACHE_TTL):
        self.api_key = api_key if api_key is not None else os.environ.get("NVD_API_KEY", "")
        self.delay = 0.7 if self.api_key else 6.5
        self._fetch = fetch
        self._sleep = sleep
        self._last_call = 0.0
        self.requests = 0
        self.cache_hits = 0
        self.cache_dir = cache_dir
        self.cache_ttl = cache_ttl
        if cache_dir:
            _prune(cache_dir, cache_ttl)

    def _get(self, params: dict) -> dict:
        cached = self._cache_read(params)
        if cached is not None:
            self.cache_hits += 1
            return cached
        wait = self._last_call + self.delay - time.monotonic()
        if self.requests and wait > 0:
            self._sleep(wait)
        headers = {"apiKey": self.api_key} if self.api_key else None
        try:
            data = self._fetch(BASE_URL, params=params, headers=headers, timeout=120)
        finally:
            self._last_call = time.monotonic()
            self.requests += 1
        self._cache_write(params, data)
        return data

    def _cache_path(self, params: dict) -> Path:
        key = hashlib.sha1(json.dumps(params, sort_keys=True).encode()).hexdigest()[:20]
        return self.cache_dir / f"{key}.json.gz"

    def _cache_read(self, params: dict) -> dict | None:
        if not self.cache_dir:
            return None
        path = self._cache_path(params)
        if not path.exists() or time.time() - path.stat().st_mtime > self.cache_ttl.total_seconds():
            return None
        try:
            return json.loads(gzip.decompress(path.read_bytes()))
        except (OSError, ValueError):
            return None

    def _cache_write(self, params: dict, data: dict) -> None:
        if not self.cache_dir:
            return
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._cache_path(params).write_bytes(gzip.compress(json.dumps(data).encode(), compresslevel=5))

    def _paged(self, params: dict) -> list[dict]:
        out, start = [], 0
        while True:
            data = self._get({**params, "resultsPerPage": PAGE_SIZE, "startIndex": start})
            out.extend(v["cve"] for v in data.get("vulnerabilities", []))
            start += data.get("resultsPerPage", 0)
            if not data.get("resultsPerPage") or start >= data.get("totalResults", 0):
                return out

    def search(self, start: datetime, end: datetime, *, date_field: str = "pub", **params) -> list[dict]:
        """기간을 120일 단위로 나눠 조회한다. date_field: 'pub'(발행일) 또는 'kev'(KEV 등재일).

        캐시 키가 실행 시각마다 달라지지 않도록 시작은 그날 00:00, 끝은 그날 23:59:59.999(UTC)로 맞춘다.
        """
        start, end = _day_start(start), _day_end(end)
        out: dict[str, dict] = {}
        cur = start
        while cur < end:
            nxt = min(cur + MAX_RANGE, end)
            rng = {f"{date_field}StartDate": _fmt(cur), f"{date_field}EndDate": _fmt(nxt)}
            for cve in self._paged({**params, **rng}):
                out[cve["id"]] = cve
            cur = nxt
        return list(out.values())


def _fmt(dt: datetime) -> str:
    # NVD 는 시간대 없는 ISO 문자열을 UTC 로 해석한다.
    return dt.astimezone(timezone.utc).replace(tzinfo=None).isoformat(timespec="milliseconds")


def _day_start(dt: datetime) -> datetime:
    return dt.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


def _day_end(dt: datetime) -> datetime:
    return dt.astimezone(timezone.utc).replace(hour=23, minute=59, second=59, microsecond=999000)


def _prune(cache_dir: Path, ttl: timedelta) -> None:
    """만료된 캐시 파일을 지운다."""
    if not cache_dir.exists():
        return
    cutoff = time.time() - ttl.total_seconds()
    for f in cache_dir.glob("*.json.gz"):
        if f.stat().st_mtime < cutoff:
            f.unlink(missing_ok=True)


# ---------------------------------------------------------------- 정규화

def _pick_cvss(metrics: dict) -> dict | None:
    """버전이 높은 것(4.0 > 3.1 > 3.0)을 우선하고, 같은 버전이면 NVD(Primary) 점수를 우선한다."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        entries = [m for m in metrics.get(key, []) if "cvssData" in m]
        if not entries:
            continue
        entries.sort(key=lambda m: m.get("type") != "Primary")
        m = entries[0]
        d = m["cvssData"]
        return {
            "score": d.get("baseScore"),
            "severity": d.get("baseSeverity") or m.get("baseSeverity"),
            "version": d.get("version"),
            "vector": d.get("vectorString"),
            "source": m.get("source"),
        }
    return None


def _ssvc(metrics: dict) -> dict | None:
    for m in metrics.get("ssvcV203", []) + metrics.get("ssvcV2", []):
        opts = {}
        for o in m.get("ssvcData", {}).get("options", []):
            opts.update(o)
        if opts:
            return {
                "exploitation": opts.get("exploitation"),
                "automatable": opts.get("automatable"),
                "technical_impact": opts.get("technicalImpact"),
            }
    return None


def _cpe_matches(cve: dict) -> list[dict]:
    out = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                parts = m["criteria"].split(":")
                out.append({
                    "vendor": parts[3] if len(parts) > 3 else "",
                    "product": parts[4] if len(parts) > 4 else "",
                    "version": parts[5] if len(parts) > 5 else "*",
                    **{k: m[k] for k in ("versionStartIncluding", "versionStartExcluding",
                                         "versionEndIncluding", "versionEndExcluding") if k in m},
                })
    return out


def _affected(cve: dict) -> list[dict]:
    out = []
    for a in cve.get("affected", []):
        for d in a.get("affectedData", []):
            out.append({
                "vendor": d.get("vendor", ""),
                "product": d.get("product", ""),
                "versions": d.get("versions", []),
            })
    return out


def normalize(cve: dict) -> dict:
    metrics = cve.get("metrics", {})
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    refs = cve.get("references", [])
    return {
        "id": cve["id"],
        "published": cve.get("published"),
        "last_modified": cve.get("lastModified"),
        "status": cve.get("vulnStatus"),
        "description": desc,
        "cvss": _pick_cvss(metrics),
        "ssvc": _ssvc(metrics),
        "kev_added": cve.get("cisaExploitAdd"),
        "kev_name": cve.get("cisaVulnerabilityName"),
        "cwe": sorted({d["value"] for w in cve.get("weaknesses", []) for d in w.get("description", [])
                       if d.get("value", "").startswith("CWE-")}),
        "cpes": _cpe_matches(cve),
        "affected": _affected(cve),
        "references": [{"url": r["url"], "tags": r.get("tags", [])} for r in refs],
        "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
    }
