from datetime import datetime, timedelta, timezone

import pytest

from pipeline import collect_cve, scoring
from pipeline.collectors import nvd
from pipeline.matching import match_reason, module_rule, version_affected, version_key

CFG = {"epss_high": 0.1, "cvss_critical": 9.0, "cvss_high": 7.0, "top_n": 20,
       "default_window_days": 30, "expand_window_days": [30, 90, 365], "min_results": 10}

MODULES = {"nginx": {"keyword": "nginx", "cpes": ["f5:nginx"], "products": ["nginx open source"]}}


def raw_cve(cve_id="CVE-2026-0001", *, score=None, version="3.1", cpes=(), affected=(), kev=None,
            exploitation=None, published="2026-10-01T00:00:00.000", status="Analyzed"):
    metrics = {}
    if score is not None:
        key = {"4.0": "cvssMetricV40", "3.1": "cvssMetricV31"}[version]
        metrics[key] = [{"source": "nvd@nist.gov", "type": "Primary",
                         "cvssData": {"version": version, "baseScore": score, "baseSeverity": "X"}}]
    if exploitation:
        metrics["ssvcV203"] = [{"ssvcData": {"options": [{"exploitation": exploitation}]}}]
    cve = {
        "id": cve_id, "published": published, "vulnStatus": status,
        "descriptions": [{"lang": "en", "value": "desc"}], "metrics": metrics, "references": [],
        "configurations": [{"nodes": [{"cpeMatch": [{"vulnerable": True, **c} for c in cpes]}]}],
        "affected": [{"affectedData": list(affected)}],
    }
    if kev:
        cve["cisaExploitAdd"] = kev
    return cve


# ---------------------------------------------------------------- NVD 정규화 / 클라이언트

def test_normalize_prefers_v4_then_primary():
    raw = raw_cve(score=9.8)
    raw["metrics"]["cvssMetricV40"] = [
        {"source": "cna", "type": "Secondary", "cvssData": {"version": "4.0", "baseScore": 9.2}},
    ]
    c = nvd.normalize(raw)
    assert c["cvss"]["version"] == "4.0" and c["cvss"]["score"] == 9.2


def test_normalize_ignores_ssvc_entries_without_cvss():
    c = nvd.normalize(raw_cve(score=8.0, exploitation="poc"))
    assert c["cvss"]["score"] == 8.0
    assert c["ssvc"]["exploitation"] == "poc"


def test_normalize_parses_cpe_and_affected():
    c = nvd.normalize(raw_cve(
        cpes=[{"criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", "versionEndExcluding": "1.30.4"}],
        affected=[{"vendor": "F5", "product": "NGINX Open Source", "versions": []}]))
    assert c["cpes"][0]["vendor"] == "f5" and c["cpes"][0]["versionEndExcluding"] == "1.30.4"
    assert c["affected"][0]["product"] == "NGINX Open Source"


def test_client_splits_range_and_pages():
    calls = []

    def fake_fetch(url, params, headers, timeout):
        calls.append(params)
        start = params["startIndex"]
        total = 3
        vulns = [{"cve": {"id": f"CVE-{params['pubStartDate'][:10]}-{start}"}}] if start < total else []
        return {"resultsPerPage": 1 if vulns else 0, "totalResults": total, "vulnerabilities": vulns}

    client = nvd.NvdClient(api_key="k", fetch=fake_fetch, sleep=lambda s: None, cache_dir=None)
    end = datetime(2026, 10, 31, 15, 30, tzinfo=timezone.utc)
    out = client.search(end - timedelta(days=200), end, keywordSearch="nginx")
    ranges = {c["pubStartDate"] for c in calls}
    assert len(ranges) == 2                      # 200일 → 119일 + 나머지
    assert len(out) == 6                          # 구간마다 3페이지
    assert all(c["keywordSearch"] == "nginx" for c in calls)
    # 캐시 키가 실행 시각에 따라 바뀌지 않도록 하루 단위로 맞춘다
    assert min(ranges) == "2026-04-14T00:00:00.000"
    assert max(c["pubEndDate"] for c in calls) == "2026-10-31T23:59:59.999"


def test_client_cache_skips_repeat_requests(tmp_path):
    calls = []

    def fake_fetch(url, params, headers, timeout):
        calls.append(params)
        return {"resultsPerPage": 1, "totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2026-1"}}]}

    end = datetime(2026, 10, 31, tzinfo=timezone.utc)
    for _ in range(2):
        client = nvd.NvdClient(api_key="k", fetch=fake_fetch, sleep=lambda s: None, cache_dir=tmp_path)
        assert [c["id"] for c in client.search(end - timedelta(days=10), end)] == ["CVE-2026-1"]
    assert len(calls) == 1
    assert client.cache_hits == 1 and client.requests == 0


# ---------------------------------------------------------------- 매칭

def test_match_by_cpe_product_and_reject_others():
    rule = module_rule("nginx", MODULES)
    by_cpe = nvd.normalize(raw_cve(cpes=[{"criteria": "cpe:2.3:a:f5:nginx:1.2.3:*:*:*:*:*:*:*"}]))
    by_product = nvd.normalize(raw_cve(affected=[{"vendor": "F5", "product": "NGINX  Open Source", "versions": []}]))
    other = nvd.normalize(raw_cve(affected=[{"vendor": "x", "product": "Frigate", "versions": []}]))
    assert match_reason(by_cpe, rule) == "cpe"
    assert match_reason(by_product, rule) == "product"
    assert match_reason(other, rule) is None


def test_unknown_module_falls_back_to_keyword():
    rule = module_rule("Tomcat", MODULES)
    assert rule["quality"] == "keyword"
    c = nvd.normalize(raw_cve(affected=[{"vendor": "Apache", "product": "Apache Tomcat", "versions": []}]))
    assert match_reason(c, rule) == "keyword"


def test_version_key_orders_numerically():
    assert version_key("1.24.10") > version_key("1.24.9")
    assert version_key("1.30") < version_key("1.30.1")


@pytest.mark.parametrize("version,expected", [("1.30.3", True), ("1.30.4", False), ("0.8.10", False)])
def test_version_affected_from_cna_range(version, expected):
    rule = module_rule("nginx", MODULES)
    c = nvd.normalize(raw_cve(affected=[{"vendor": "F5", "product": "NGINX Open Source", "versions": [
        {"version": "0.8.11", "lessThan": "1.30.4", "status": "affected"}]}]))
    assert version_affected(c, rule, version) is expected


def test_version_affected_from_cpe_range_and_unknown():
    rule = module_rule("nginx", MODULES)
    c = nvd.normalize(raw_cve(cpes=[{"criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                                     "versionStartIncluding": "1.25.0", "versionEndExcluding": "1.27.1"}]))
    assert version_affected(c, rule, "1.26.0") is True
    assert version_affected(c, rule, "1.27.1") is False
    no_info = nvd.normalize(raw_cve(cpes=[{"criteria": "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"}]))
    assert version_affected(no_info, rule, "1.26.0") is None


@pytest.mark.parametrize("version,expected", [
    ("1.30.5", False),   # 1.30 브랜치 전용 범위(1.30.2 ≤ v < 1.30.3)가 우선 → 이미 고쳐짐
    ("1.30.2", True),
    ("1.31.1", True),    # 1.31 브랜치는 넓은 범위(< 1.31.2)에 해당
    ("1.28.0", True),    # 브랜치 전용 범위가 없으면 넓은 범위로 판단
    ("1.31.2", False),
])
def test_version_affected_prefers_same_branch_range(version, expected):
    rule = module_rule("nginx", MODULES)
    c = nvd.normalize(raw_cve(affected=[{"vendor": "F5", "product": "NGINX Open Source", "versions": [
        {"version": "1.13.10", "lessThan": "1.31.2", "status": "affected"},
        {"version": "1.30.2", "lessThan": "1.30.3", "status": "affected"}]}]))
    assert version_affected(c, rule, version) is expected


def test_version_affected_handles_wildcard_branch_bases():
    rule = module_rule("php", {"php": {"keyword": "php", "cpes": [], "products": ["php"]}})
    c = nvd.normalize(raw_cve(affected=[{"vendor": "PHP Group", "product": "PHP", "versions": [
        {"version": "8.2.*", "lessThan": "8.2.35", "status": "affected"},
        {"version": "8.3.*", "lessThan": "8.3.36", "status": "affected"}]}]))
    assert version_affected(c, rule, "8.3.10") is True
    assert version_affected(c, rule, "8.3.36") is False
    assert version_affected(c, rule, "8.2.40") is False


# ---------------------------------------------------------------- 등급

@pytest.mark.parametrize("fields,tier", [
    ({"kev": {"ransomware": True}, "cvss": {"score": 5.0}}, "S"),
    ({"ssvc": {"exploitation": "active"}}, "S"),
    ({"epss": {"epss": 0.25}, "cvss": {"score": 5.0}}, "A"),
    ({"cvss": {"score": 9.8}, "pocs": ["https://github.com/x"]}, "A"),
    ({"cvss": {"score": 9.8}, "ssvc": {"exploitation": "poc"}}, "A"),
    ({"cvss": {"score": 9.8}}, "B"),
    ({"cvss": {"score": 7.0}}, "B"),
    ({"cvss": {"score": 6.9}}, "C"),
    ({}, "C"),
])
def test_grade(fields, tier):
    assert scoring.grade(fields, CFG)[0] == tier


def test_enrich_and_rank_orders_by_tier_then_recency():
    cves = [nvd.normalize(c) for c in [
        raw_cve("CVE-2026-0001", score=7.5, published="2026-10-20T00:00:00.000"),
        raw_cve("CVE-2026-0002", score=9.8, published="2026-10-01T00:00:00.000"),
        raw_cve("CVE-2026-0003", score=5.0, published="2026-10-25T00:00:00.000", kev="2026-10-26"),
        raw_cve("CVE-2026-0004", score=8.0, published="2026-10-28T00:00:00.000"),
    ]]
    ranked = collect_cve.enrich_and_rank(
        cves, {}, CFG,
        epss_fn=lambda ids: {},
        poc_fn=lambda cs: {c["id"]: (["https://github.com/poc"] if c["id"] == "CVE-2026-0002" else []) for c in cs},
    )[:3]
    assert [c["id"] for c in ranked] == ["CVE-2026-0003", "CVE-2026-0002", "CVE-2026-0004"]
    assert [c["tier"] for c in ranked] == ["S", "A", "B"]


def _graded(cve_id, tier, published, **fields):
    return {"id": cve_id, "tier": tier, "published": published, **fields}


def test_sort_within_tier_uses_risk_signal():
    cves = [
        # A: EPSS 로 A 가 된 것은 EPSS 높은 순, CVSS+PoC 로 A 가 된 것은 그 뒤에 최신순
        _graded("A-poc-new", "A", "2026-10-14", epss={"epss": 0.008}, cvss={"score": 9.2}),
        _graded("A-epss-68", "A", "2026-05-13", epss={"epss": 0.68}, cvss={"score": 9.2}),
        _graded("A-epss-25", "A", "2026-03-24", epss={"epss": 0.25}, cvss={"score": 8.8}),
        _graded("A-poc-old", "A", "2026-06-17", epss={"epss": 0.06}, cvss={"score": 9.2}),
        # S: 랜섬웨어 악용 → KEV 등재일 최신순
        _graded("S-kev-old", "S", "2026-10-20", kev={"date_added": "2026-10-21"}),
        _graded("S-kev-new", "S", "2026-09-01", kev={"date_added": "2026-10-29"}),
        _graded("S-ransom", "S", "2026-01-01", kev={"date_added": "2026-02-01", "ransomware": True}),
        # B: CVSS 높은 순
        _graded("B-8.3", "B", "2026-10-14", cvss={"score": 8.3}),
        _graded("B-8.8", "B", "2026-07-15", cvss={"score": 8.8}),
    ]
    ordered = [c["id"] for c in sorted(cves, key=lambda c: scoring.sort_key(c, CFG))]
    assert ordered == ["S-ransom", "S-kev-new", "S-kev-old",
                       "A-epss-68", "A-epss-25", "A-poc-new", "A-poc-old",
                       "B-8.8", "B-8.3"]


def test_collect_all_separates_exploited_from_top_n(monkeypatch):
    raws = [raw_cve(f"CVE-2026-{i:04d}", score=9.8, kev="2026-10-20") for i in range(5)]
    raws += [raw_cve(f"CVE-2026-1{i:03d}", score=9.5) for i in range(3)]
    raws += [raw_cve("CVE-2026-2000", score=7.5)]

    class FakeClient:
        def search(self, start, end, date_field="pub", **params):
            return raws if date_field == "pub" else []

    monkeypatch.setattr(collect_cve, "load_epss", lambda ids: {})
    monkeypatch.setattr(collect_cve, "find_pocs", lambda cs: {})
    cfg = {**CFG, "top_n": 4, "all_exploited_max": 3}
    report = collect_cve.collect_all(FakeClient(), cfg, {}, days=30)
    assert report["exploited_total"] == 5
    assert len(report["exploited"]) == 3 and all(c["tier"] == "S" for c in report["exploited"])
    # Top N 은 S 를 빼고 채우고, CVSS 9 이상 후보가 모자라면 7 이상으로 넓힌다
    assert [c["tier"] for c in report["items"]] == ["B", "B", "B", "B"]
    assert report["items"][-1]["id"] == "CVE-2026-2000"
