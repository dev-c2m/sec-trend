"""공개 PoC 확인: nomi-sec/PoC-in-GitHub 모음 + NVD 참조 링크의 'Exploit' 태그."""
import json
import urllib.error
from concurrent.futures import ThreadPoolExecutor

from pipeline.common import http_get

POC_URL = "https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/master/{year}/{cve}.json"
MAX_LINKS = 3


def github_pocs(cve_id: str, fetch=http_get) -> list[str]:
    year = cve_id.split("-")[1]
    try:
        repos = json.loads(fetch(POC_URL.format(year=year, cve=cve_id), timeout=20))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []
        raise
    repos.sort(key=lambda r: r.get("stargazers_count", 0), reverse=True)
    return [r["html_url"] for r in repos[:MAX_LINKS] if r.get("html_url")]


def find_pocs(cves: list[dict], fetch=http_get) -> dict[str, list[str]]:
    """{CVE ID: [PoC 링크]}. 조회에 실패한 CVE 는 NVD Exploit 태그만으로 판단한다."""
    def work(cve):
        links = [r["url"] for r in cve.get("references", []) if "Exploit" in r.get("tags", [])][:MAX_LINKS]
        try:
            links = github_pocs(cve["id"], fetch) + links
        except Exception:
            pass
        return cve["id"], list(dict.fromkeys(links))[:MAX_LINKS]

    with ThreadPoolExecutor(max_workers=8) as pool:
        return dict(pool.map(work, cves))
