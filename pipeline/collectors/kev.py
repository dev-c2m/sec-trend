"""CISA KEV(Known Exploited Vulnerabilities) 카탈로그. 하루 한 번만 내려받아 캐시한다."""
from pipeline.common import OUTPUT_DIR, http_get_json, read_json, today_str, write_json

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_DIR = OUTPUT_DIR / "cache"


def load_kev(fetch=http_get_json) -> dict[str, dict]:
    """{CVE ID: {date_added, ransomware, name, required_action, due_date}}"""
    path = CACHE_DIR / f"kev-{today_str()}.json"
    data = read_json(path)
    if data is None:
        data = fetch(KEV_URL, timeout=60)
        write_json(path, data)
        for old in CACHE_DIR.glob("kev-*.json"):
            if old != path:
                old.unlink()
    return {
        v["cveID"]: {
            "date_added": v.get("dateAdded"),
            "ransomware": v.get("knownRansomwareCampaignUse") == "Known",
            "name": v.get("vulnerabilityName"),
            "required_action": v.get("requiredAction"),
            "due_date": v.get("dueDate"),
        }
        for v in data.get("vulnerabilities", [])
    }
