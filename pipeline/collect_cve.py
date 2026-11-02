"""CVE 수집 진입점.

사용법 (프로젝트 루트에서):
    python -m pipeline.collect_cve                          # watchlist 의 모듈 전부
    python -m pipeline.collect_cve --module nginx           # 모듈 하나
    python -m pipeline.collect_cve --module nginx --version 1.24.0
    python -m pipeline.collect_cve --all                    # 전체 CVE 중 고위험 Top N
    python -m pipeline.collect_cve --module php --days 90   # 기간 고정 (자동 확장 안 함)

결과: output/cve/YYYY-MM-DD-<모듈|watchlist|all>.json
"""
import argparse
from datetime import timedelta

from pipeline import scoring
from pipeline.collectors import nvd
from pipeline.collectors.epss import load_epss
from pipeline.collectors.kev import load_kev
from pipeline.collectors.poc import find_pocs
from pipeline.common import OUTPUT_DIR, load_env, load_toml, now_kst, today_str, utf8_stdout, write_json
from pipeline.matching import match_reason, module_rule, version_affected

CVE_DIR = OUTPUT_DIR / "cve"
COMPONENT_TOP_N = 5
POC_LOOKUP_LIMIT = 150
REF_PRIORITY = ("Vendor Advisory", "Patch", "Mitigation", "Release Notes", "Third Party Advisory")


# ---------------------------------------------------------------- 등급 매기기

def enrich_and_rank(cves: list[dict], kev_map: dict, cfg: dict,
                    *, epss_fn=None, poc_fn=None) -> list[dict]:
    """KEV·EPSS·PoC 를 붙이고 등급을 매겨 위험도 순으로 정렬한 전체 목록을 돌려준다.

    화면에 보여줄 항목은 호출한 쪽에서 잘라낸 뒤 attach_display_pocs 로 PoC 를 채운다.
    """
    if not cves:
        return []
    # 기본값을 호출 시점에 찾아야 테스트의 monkeypatch 가 적용된다.
    epss_fn = epss_fn or load_epss
    poc_fn = poc_fn or find_pocs
    epss = epss_fn([c["id"] for c in cves])
    for c in cves:
        kev = kev_map.get(c["id"])
        if kev is None and c.get("kev_added"):
            kev = {"date_added": c["kev_added"], "ransomware": False, "name": c.get("kev_name")}
        c["kev"] = kev
        c["epss"] = epss.get(c["id"])
        c["pocs"] = []
        c["tier"], c["reasons"] = scoring.grade(c, cfg)

    # PoC 는 등급을 B → A 로 올릴 수 있는 CVE(CVSS 치명적, 아직 A 미만)만 먼저 조회한다.
    upgradable = [c for c in cves if c["tier"] in ("B", "C")
                  and ((c.get("cvss") or {}).get("score") or 0) >= cfg["cvss_critical"]]
    _attach_pocs(upgradable[:POC_LOOKUP_LIMIT], poc_fn)
    for c in upgradable:
        c["tier"], c["reasons"] = scoring.grade(c, cfg)

    return sorted(cves, key=lambda c: scoring.sort_key(c, cfg))


def attach_display_pocs(cves: list[dict], poc_fn=None) -> None:
    """화면에 보여줄 항목 중 아직 PoC 를 조회하지 않은 것을 채운다."""
    _attach_pocs([c for c in cves if not c.get("_poc_checked")], poc_fn or find_pocs)


def _attach_pocs(cves: list[dict], poc_fn) -> None:
    if cves:
        found = poc_fn(cves)
        for c in cves:
            c["pocs"] = found.get(c["id"], [])
            c["_poc_checked"] = True


def tier_counts(cves: list[dict]) -> dict:
    counts = {t: 0 for t in scoring.TIER_ORDER}
    for c in cves:
        counts[c["tier"]] += 1
    return counts


# ---------------------------------------------------------------- 출력용 정리

def _affected_summary(cve: dict, rule: dict | None) -> list[str]:
    products = {p.lower() for p in (rule or {}).get("products", [])}
    out = []
    for a in cve["affected"]:
        if products and a["product"].strip().lower() not in products:
            continue
        ranges = []
        for v in a["versions"]:
            if v.get("status", "affected") != "affected":
                continue
            base = v.get("version", "")
            if v.get("lessThan"):
                ranges.append(f"{base} ≤ v < {v['lessThan']}")
            elif v.get("lessThanOrEqual"):
                ranges.append(f"{base} ≤ v ≤ {v['lessThanOrEqual']}")
            elif base:
                ranges.append(base)
        out.append(f"{a['vendor']} {a['product']}: " + (", ".join(ranges[:4]) or "버전 정보 없음"))
    if not out:
        cpes = {c.lower() for c in (rule or {}).get("cpes", [])}
        for c in cve["cpes"]:
            if cpes and f"{c['vendor']}:{c['product']}".lower() not in cpes:
                continue
            lo = c.get("versionStartIncluding") or c.get("versionStartExcluding") or ""
            hi = c.get("versionEndExcluding") or c.get("versionEndIncluding") or ""
            rng = f"{lo} ~ {hi}".strip(" ~") if (lo or hi) else c["version"]
            out.append(f"{c['vendor']}:{c['product']} {rng}")
    return list(dict.fromkeys(out))[:4]


def _top_refs(cve: dict) -> list[dict]:
    def prio(r):
        tags = r.get("tags", [])
        return min((REF_PRIORITY.index(t) for t in tags if t in REF_PRIORITY), default=len(REF_PRIORITY))
    return [{"url": r["url"], "tags": r.get("tags", [])} for r in sorted(cve["references"], key=prio)[:3]]


def to_output(cve: dict, rule: dict | None) -> dict:
    return {
        "id": cve["id"],
        "tier": cve["tier"],
        "reasons": cve["reasons"],
        "published": (cve.get("published") or "")[:10],
        "nvd_status": cve.get("status"),
        "cvss": cve.get("cvss"),
        "epss": cve.get("epss"),
        "kev": cve.get("kev"),
        "ssvc": cve.get("ssvc"),
        "pocs": cve.get("pocs", []),
        "match": cve.get("match"),
        "version_affected": cve.get("version_affected"),
        "affected": _affected_summary(cve, rule),
        "cwe": cve.get("cwe", []),
        "description": cve["description"],
        "references": _top_refs(cve),
        "nvd_url": cve["nvd_url"],
    }


# ---------------------------------------------------------------- 모듈 모드

def collect_module(client, rule: dict, version: str | None, cfg: dict, kev_map: dict,
                   *, fixed_days: int | None = None, top_n: int | None = None,
                   with_components: bool = True, modules: dict | None = None) -> dict:
    windows = [fixed_days] if fixed_days else cfg["expand_window_days"]
    now = now_kst()
    matched: dict[str, dict] = {}
    fetched_days = 0
    for days in windows:
        # 이미 받은 기간은 건너뛰고 늘어난 부분만 조회한다.
        raw = client.search(now - timedelta(days=days), now - timedelta(days=fetched_days),
                            keywordSearch=rule["keyword"])
        fetched_days = days
        for r in raw:
            c = nvd.normalize(r)
            if c["status"] == "Rejected":
                continue
            reason = match_reason(c, rule)
            if not reason:
                continue
            c["match"] = reason
            if version:
                c["version_affected"] = version_affected(c, rule, version)
                if c["version_affected"] is False:
                    continue
            matched[c["id"]] = c
        if len(matched) >= cfg["min_results"]:
            break

    all_matched = list(matched.values())
    ranked = enrich_and_rank(all_matched, kev_map, cfg)[:top_n or cfg["top_n"]]
    attach_display_pocs(ranked)
    report = {
        "module": rule["name"],
        "version": version or None,
        "match_quality": rule["quality"],
        "window_days": fetched_days,
        "total_matched": len(all_matched),
        "tier_counts": tier_counts(all_matched),
        "items": [to_output(c, rule) for c in ranked],
        "components": [],
    }
    if with_components:
        for comp in rule.get("components", []):
            comp_rule = module_rule(comp, modules or {})
            sub = collect_module(client, comp_rule, None, cfg, kev_map, fixed_days=fetched_days,
                                 top_n=COMPONENT_TOP_N, with_components=False)
            report["components"].append(sub)
    return report


# ---------------------------------------------------------------- 전체 모드

def collect_all(client, cfg: dict, kev_map: dict, days: int) -> dict:
    now = now_kst()
    start = now - timedelta(days=days)
    raw = {r["id"]: r for r in client.search(start, now)}
    # 오래전에 공개됐지만 이 기간에 새로 KEV 에 오른 CVE 도 포함한다.
    raw.update({r["id"]: r for r in client.search(start, now, date_field="kev")})

    cves = [c for c in map(nvd.normalize, raw.values()) if c["status"] != "Rejected"]
    for c in cves:
        c["match"] = "all"

    def is_candidate(c, min_score):
        score = (c.get("cvss") or {}).get("score") or 0
        exploitation = (c.get("ssvc") or {}).get("exploitation")
        return (c.get("kev_added") or c["id"] in kev_map or exploitation in ("active", "poc")
                or score >= min_score)

    # 전체 CVE 는 수만 건이라 EPSS 조회 대상을 먼저 줄인다.
    candidates = [c for c in cves if is_candidate(c, cfg["cvss_critical"])]
    ranked = enrich_and_rank(candidates, kev_map, cfg)
    # 실제 악용(S)은 기간 안에 수십 건이라 Top N 을 다 차지한다. 별도 목록으로 빼고,
    # Top N 은 아직 악용이 확인되지 않은 고위험(A·B) CVE 로 채운다.
    exploited = [c for c in ranked if c["tier"] == "S"][:cfg["all_exploited_max"]]
    others = [c for c in ranked if c["tier"] != "S"][:cfg["top_n"]]
    if len(others) < cfg["top_n"]:
        seen = {c["id"] for c in candidates}
        extra = [c for c in cves if c["id"] not in seen and is_candidate(c, cfg["cvss_high"])]
        others = (others + enrich_and_rank(extra, kev_map, cfg))[:cfg["top_n"]]
    attach_display_pocs(exploited + others)
    return {
        "module": "all",
        "version": None,
        "match_quality": "all",
        "window_days": days,
        "total_matched": len(cves),
        "candidates": len(candidates),
        "tier_counts": tier_counts(candidates),
        "exploited": [to_output(c, None) for c in exploited],
        "exploited_total": sum(1 for c in ranked if c["tier"] == "S"),
        "items": [to_output(c, None) for c in others],
        "components": [],
    }


# ---------------------------------------------------------------- 진입점

def main(argv=None) -> None:
    utf8_stdout()
    p = argparse.ArgumentParser(description="CVE 수집 + 위험도 등급")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--module", help="모듈 이름 (예: nginx, php, opnsense)")
    g.add_argument("--all", action="store_true", help="전체 CVE 중 고위험 Top N")
    p.add_argument("--version", help="모듈 버전 (예: 1.24.0). 해당 버전에 영향 있는 CVE 만")
    p.add_argument("--days", type=int, help="조회 기간(일). 지정하면 자동 확장하지 않는다")
    p.add_argument("--date", default=today_str(), help="저장 파일 날짜 (YYYY-MM-DD)")
    p.add_argument("--no-cache", action="store_true", help="NVD 응답 캐시를 쓰지 않고 새로 받는다")
    args = p.parse_args(argv)

    load_env()
    cfg = load_toml("scoring.toml")
    modules = load_toml("modules.toml").get("modules", {})
    client = nvd.NvdClient(cache_dir=None if args.no_cache else nvd.CACHE_DIR)
    kev_map = load_kev()
    if not client.api_key:
        print("[cve] NVD_API_KEY 가 없어 새 요청 사이에 6.5초씩 쉽니다. 프로젝트 루트 .env 에 "
              "NVD_API_KEY=... 를 넣으면 10배 빨라집니다. (발급: https://nvd.nist.gov/developers/request-an-api-key)")

    if args.all:
        label, reports = "all", [collect_all(client, cfg, kev_map, args.days or cfg["default_window_days"])]
    elif args.module:
        label = args.module.lower() + (f"-{args.version}" if args.version else "")
        reports = [collect_module(client, module_rule(args.module, modules), args.version, cfg, kev_map,
                                  fixed_days=args.days, modules=modules)]
    else:
        label = "watchlist"
        reports = [collect_module(client, module_rule(w["module"], modules), w.get("version") or None, cfg,
                                  kev_map, fixed_days=args.days, modules=modules)
                   for w in load_toml("watchlist.toml").get("watch", [])]

    result = {
        "generated_at": now_kst().isoformat(timespec="seconds"),
        "date": args.date,
        "mode": "all" if args.all else ("module" if args.module else "watchlist"),
        "criteria": {k: cfg[k] for k in ("epss_high", "cvss_critical", "cvss_high", "top_n")},
        "reports": reports,
    }
    out = CVE_DIR / f"{args.date}-{label}.json"
    write_json(out, result)

    for r in reports:
        ver = f" {r['version']}" if r["version"] else ""
        print(f"[cve] {r['module']}{ver}: 최근 {r['window_days']}일, 매칭 {r['total_matched']}건 → 상위 {len(r['items'])}건 "
              f"{r['tier_counts']}")
        if "exploited" in r:
            print(f"      └ 실제 악용(S) {r['exploited_total']}건 중 {len(r['exploited'])}건은 별도 목록")
        for comp in r["components"]:
            print(f"      └ 구성요소 {comp['module']}: 매칭 {comp['total_matched']}건 → {len(comp['items'])}건")
    print(f"[cve] NVD 요청 {client.requests}회, 캐시 사용 {client.cache_hits}회")
    print(f"[cve] 저장: {out}")


if __name__ == "__main__":
    main()
