"""공통 유틸: 경로, 시간대, HTTP, 설정 로딩."""
import json
import os
import re
import sys
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG_DIR = ROOT / "config"
OUTPUT_DIR = ROOT / "output"

# Windows 에는 tzdata 가 없을 수 있어 zoneinfo 대신 고정 오프셋을 쓴다.
KST = timezone(timedelta(hours=9), "KST")

USER_AGENT = "Mozilla/5.0 (compatible; sec-trend/0.1; +https://github.com/)"


def now_kst() -> datetime:
    return datetime.now(KST)


def today_str() -> str:
    return now_kst().strftime("%Y-%m-%d")


def parse_duration(text: str) -> timedelta:
    """'24h', '3d', '2w' 형식을 timedelta 로 변환한다."""
    m = re.fullmatch(r"\s*(\d+)\s*([hdw])\s*", text.lower())
    if not m:
        raise ValueError(f"기간 형식이 올바르지 않습니다: {text!r} (예: 24h, 3d, 1w)")
    n, unit = int(m.group(1)), m.group(2)
    return {"h": timedelta(hours=n), "d": timedelta(days=n), "w": timedelta(weeks=n)}[unit]


def load_toml(name: str) -> dict:
    with open(CONFIG_DIR / name, "rb") as f:
        return tomllib.load(f)


def http_get(url: str, *, params: dict | None = None, headers: dict | None = None,
             timeout: int = 30, retries: int = 2) -> bytes:
    """GET 요청. 5xx/네트워크 오류는 재시도하고, 404 는 바로 예외를 올린다."""
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    req_headers = {"User-Agent": USER_AGENT}
    if headers:
        req_headers.update(headers)
    last_err: Exception | None = None
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=req_headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            last_err = e
            if e.code < 500 and e.code != 429:
                raise
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            last_err = e
        if attempt < retries:
            time.sleep(2 * (attempt + 1))
    assert last_err is not None
    raise last_err


def http_get_json(url: str, **kwargs) -> dict:
    return json.loads(http_get(url, **kwargs).decode("utf-8"))


def write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def read_json(path: Path, default=None):
    if not path.exists():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def load_env(path: Path = ROOT / ".env") -> None:
    """프로젝트 루트 .env 의 KEY=VALUE 를 환경변수로 읽는다. 이미 설정된 환경변수가 우선한다."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def utf8_stdout() -> None:
    """Windows 콘솔에서 한글 출력이 깨지지 않게 한다."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
