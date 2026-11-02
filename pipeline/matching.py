"""CVE ↔ 모듈 매칭과 버전 해당 여부 판단."""
import re

VERSION_TOKEN = re.compile(r"\d+|[a-z]+")


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())


def module_rule(name: str, modules: dict) -> dict:
    """설정에 없는 모듈은 키워드 기반 규칙을 만든다 (quality='keyword')."""
    name = name.lower()
    if name in modules:
        return {"name": name, "quality": "exact", "components": [], **modules[name]}
    return {"name": name, "quality": "keyword", "keyword": name, "cpes": [], "products": [], "components": []}


def match_reason(cve: dict, rule: dict) -> str | None:
    """CVE 가 모듈에 해당하면 근거('cpe' | 'product' | 'keyword')를, 아니면 None 을 돌려준다."""
    cpes = {c.lower() for c in rule.get("cpes", [])}
    for c in cve["cpes"]:
        if f"{c['vendor']}:{c['product']}".lower() in cpes:
            return "cpe"
    products = {_norm(p) for p in rule.get("products", [])}
    for a in cve["affected"]:
        if _norm(a["product"]) in products:
            return "product"
    if rule["quality"] == "keyword":
        kw = _norm(rule["keyword"])
        for c in cve["cpes"]:
            if kw in c["product"].lower().replace("_", " "):
                return "keyword"
        for a in cve["affected"]:
            if kw in _norm(a["product"]):
                return "keyword"
    return None


# ---------------------------------------------------------------- 버전 비교

def version_key(v: str) -> tuple:
    """'1.24.0' < '1.24.10', '2.4.0-rc1' 같은 문자열을 비교 가능한 튜플로 바꾼다."""
    out = []
    for tok in VERSION_TOKEN.findall(v.lower()):
        out.append((1, int(tok), "") if tok.isdigit() else (0, 0, tok))
    return tuple(out)


NO_VERSION = ("", "*", "-", "0", "n/a")


def _branch(v: str | None) -> tuple:
    """버전의 앞 두 숫자(major.minor). '1.30.5' → (1, 30), '8.2.*' → (8, 2)."""
    nums = [int(t) for t in VERSION_TOKEN.findall((v or "").lower()) if t.isdigit()]
    return tuple(nums[:2]) if len(nums) >= 2 else ()


def _in_range(v: str, r: dict) -> bool:
    k = version_key(v)
    if r.get("exact"):
        return k == version_key(r["exact"])
    if r.get("start") and k < version_key(r["start"]):
        return False
    if r.get("start_excl") and k <= version_key(r["start_excl"]):
        return False
    if r.get("end") and k > version_key(r["end"]):
        return False
    if r.get("end_excl") and k >= version_key(r["end_excl"]):
        return False
    return True


def _cpe_range(c: dict) -> dict | None:
    r = {"start": c.get("versionStartIncluding"), "start_excl": c.get("versionStartExcluding"),
         "end": c.get("versionEndIncluding"), "end_excl": c.get("versionEndExcluding")}
    if any(r.values()):
        return r
    if c["version"] in NO_VERSION:
        return None
    return {"exact": c["version"]}


def _affected_range(entry: dict) -> dict | None:
    if entry.get("status", "affected") != "affected":
        return None
    base = entry.get("version", "")
    start = base if base not in NO_VERSION else None
    lt, lte = entry.get("lessThan"), entry.get("lessThanOrEqual")
    if lt == "*" or lte == "*":
        return {"start": start} if start else None
    if lt or lte:
        return {"start": start, "end": lte, "end_excl": lt}
    return {"exact": base} if start else None


def affected_ranges(cve: dict, rule: dict) -> list[dict]:
    """모듈에 해당하는 CPE·CNA 버전 범위를 한 형식으로 모은다."""
    cpes = {c.lower() for c in rule.get("cpes", [])}
    products = {_norm(p) for p in rule.get("products", [])}
    ranges = []
    for c in cve["cpes"]:
        if f"{c['vendor']}:{c['product']}".lower() in cpes:
            ranges.append(_cpe_range(c))
    for a in cve["affected"]:
        if _norm(a["product"]) in products:
            ranges.extend(_affected_range(e) for e in a["versions"])
    return [r for r in ranges if r]


def version_affected(cve: dict, rule: dict, version: str) -> bool | None:
    """True: 해당 버전 영향 있음 / False: 영향 범위 밖 / None: 버전 정보가 없어 판단 불가.

    nginx 처럼 브랜치마다 범위를 따로 적는 경우가 있다. 예) '1.13.10 ≤ v < 1.31.2'(mainline) 와
    '1.30.2 ≤ v < 1.30.3'(1.30 stable). 대상 버전과 같은 브랜치(major.minor)를 직접 가리키는 범위가 있으면
    그 범위만 보고 판단한다. 그래야 1.30.3 에서 고쳐진 1.30.5 를 넓은 범위 때문에 '해당'으로 잘못 보지 않는다.
    """
    ranges = affected_ranges(cve, rule)
    if not ranges:
        return None
    branch = _branch(version)
    if branch:
        same_branch = [r for r in ranges if any(_branch(b) == branch for b in r.values() if b)]
        if same_branch:
            ranges = same_branch
    return any(_in_range(version, r) for r in ranges)
