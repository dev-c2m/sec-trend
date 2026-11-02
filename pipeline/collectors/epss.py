"""FIRST EPSS API: 30일 내 악용될 확률."""
from pipeline.common import http_get_json

EPSS_URL = "https://api.first.org/data/v1/epss"
BATCH = 100


def load_epss(cve_ids: list[str], fetch=http_get_json) -> dict[str, dict]:
    """{CVE ID: {epss, percentile}}. EPSS 에 아직 없는 CVE 는 결과에서 빠진다."""
    out = {}
    ids = sorted(set(cve_ids))
    for i in range(0, len(ids), BATCH):
        chunk = ids[i:i + BATCH]
        data = fetch(EPSS_URL, params={"cve": ",".join(chunk), "limit": BATCH}, timeout=60)
        for row in data.get("data", []):
            out[row["cve"]] = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
    return out
