# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

보안 트렌드 수집 도구. 두 가지를 한다.

1. **보안 뉴스** — 국내·해외 보안 매체 RSS 를 수집해 같은 사건을 묶고, 카테고리별 한국어 다이제스트를 만든다.
2. **CVE** — NVD·CISA KEV·FIRST EPSS·PoC-in-GitHub 를 조합해 위험도 등급(S/A/B/C)을 매기고, 모듈(nginx, php, opnsense 등)별 고위험·최신순 Top 20 을 정리한다.

Python 수집기가 `output/` 에 JSON 을 만들고, Claude 명령어(`/secnews`, `/cve`)가 그 JSON 을 읽어 md 로 정리한다.
수집기 런타임은 Python stdlib 만 사용한다 (pytest 는 테스트용).

## Commands

```bash
# 테스트
python -m pytest pipeline/tests -v

# 보안 뉴스 수집 (기본 최근 24시간)
python -m pipeline.collect_news --since 24h

# CVE 수집
python -m pipeline.collect_cve                       # watchlist 전체
python -m pipeline.collect_cve --module nginx        # 모듈 하나
python -m pipeline.collect_cve --module nginx --version 1.24.0
python -m pipeline.collect_cve --all                 # 전체 CVE Top 20
```

## 구조

- `config/sources.toml` — 뉴스 RSS 목록
- `config/modules.toml` — 모듈 → CPE·제품명 매칭 규칙, 하위 구성요소
- `config/watchlist.toml` — 인자 없는 `/cve` 가 점검할 모듈
- `config/scoring.toml` — 등급 기준값, Top N, 기간 자동 확장 단계
- `pipeline/collectors/` — rss, nvd, kev, epss, poc 수집기
- `pipeline/matching.py` — CVE ↔ 모듈 매칭, 버전 해당 여부
- `pipeline/scoring.py` — S/A/B/C 등급
- `output/news/`, `output/cve/` — 결과 JSON·md (gitignore, 로컬 전용)
- `examples/` — README 에서 링크하는 결과 예시 md

## 커밋

[Conventional Commits](https://www.conventionalcommits.org/ko/v1.0.0/) 형식, 설명은 한국어로 쓴다.
예: `feat(cve): 등급 내 정렬 추가`, `fix(news): 상투 문구 제거`, `docs: README 설치 방법 보완`
scope 는 `news`, `cve`, `commands`, `config` 중에서 고른다.

## 주의사항

- 런타임에 외부 라이브러리를 추가하지 않는다. stdlib 만 사용한다.
- 테스트는 외부 API 를 호출하지 않는다. fetch 함수를 주입하거나 monkeypatch 로 대체한다.
- md 를 만들 때 JSON 에 없는 점수·날짜·피해 규모를 지어내지 않는다. 값이 없으면 `-` 로 둔다.
- 뉴스는 RSS 요약만 근거로 새로 써서 요약한다. 기사 본문을 그대로 옮기지 않는다.
- 등급 기준을 바꿀 때는 `config/scoring.toml` 과 `/cve` 명령어의 "등급 기준" 표를 함께 맞춘다.
- NVD API 키는 환경변수 `NVD_API_KEY` 또는 gitignore 된 `.env` 로만 읽는다. 키를 커밋하지 않는다.
- NVD 응답은 `output/cache/nvd/` 에 6시간 캐시된다 (조회 기간을 UTC 하루 단위로 맞춰 캐시 키를 고정). `--no-cache` 로 우회.
- 테스트는 `conftest.py` 가 `urllib.request.urlopen` 을 막는다. 기본 인자에 수집 함수를 직접 넣지 말고 호출 시점에 찾는다 (monkeypatch 가 먹히도록).
