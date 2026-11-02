"""CVE 위험도 등급(S/A/B/C) 계산. 기준값은 config/scoring.toml."""

TIER_ORDER = {"S": 0, "A": 1, "B": 2, "C": 3}


def grade(cve: dict, cfg: dict) -> tuple[str, list[str]]:
    """(등급, 근거 목록). cve 에는 cvss, ssvc, kev, epss, pocs 가 채워져 있어야 한다."""
    reasons = []
    score = (cve.get("cvss") or {}).get("score") or 0.0
    epss = (cve.get("epss") or {}).get("epss")
    exploitation = (cve.get("ssvc") or {}).get("exploitation")

    if cve.get("kev"):
        reasons.append("CISA KEV 등재" + (" (랜섬웨어 악용)" if cve["kev"].get("ransomware") else ""))
    if exploitation == "active":
        reasons.append("CISA SSVC: 실제 악용 확인")
    if reasons:
        return "S", reasons

    has_poc = bool(cve.get("pocs")) or exploitation == "poc"
    if epss is not None and epss >= cfg["epss_high"]:
        reasons.append(f"EPSS {epss:.1%}")
    if score >= cfg["cvss_critical"] and has_poc:
        reasons.append(f"CVSS {score} + 공개 PoC")
    if reasons:
        return "A", reasons

    if score >= cfg["cvss_high"]:
        return "B", [f"CVSS {score}"]
    return "C", [f"CVSS {score}" if score else "CVSS 미산정"]


def _date_num(text: str | None) -> int:
    """'2026-10-14...' → 20261014. 역순 정렬을 위해 숫자로 바꾼다."""
    return int((text or "0000-00-00")[:10].replace("-", "") or 0)


def sort_key(cve: dict, cfg: dict) -> tuple:
    """등급 순으로 놓고, 같은 등급 안에서는 그 등급을 만든 위험 신호가 강한 것부터 정렬한다.

    S: 랜섬웨어 악용 → KEV 등재일 최신순 (최근에 악용이 확인된 것)
    A: EPSS 기준을 넘은 것을 EPSS 높은 순으로 먼저, 나머지(CVSS+PoC)는 공개일 최신순
    B: CVSS 높은 순 → 공개일 최신순
    C: 공개일 최신순
    """
    tier = cve["tier"]
    pub = _date_num(cve.get("published"))
    epss = (cve.get("epss") or {}).get("epss") or 0.0
    score = (cve.get("cvss") or {}).get("score") or 0.0
    if tier == "S":
        kev = cve.get("kev") or {}
        signal = (-int(bool(kev.get("ransomware"))), -_date_num(kev.get("date_added")), -epss)
    elif tier == "A":
        signal = (-epss, 0) if epss >= cfg["epss_high"] else (1, -pub)
    elif tier == "B":
        signal = (-score,)
    else:
        signal = ()
    return (TIER_ORDER[tier], *signal, -pub)
