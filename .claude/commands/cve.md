# /cve [모듈] [버전] [days=N]

CVE 를 수집해 위험도 등급(S/A/B/C)을 매기고 고위험·최신순 Top 20 을 md 로 정리합니다.

## 인자 파싱 규칙

`$ARGUMENTS`를 공백으로 나눠 다음 규칙으로 해석한다:
- 인자 없음 → watchlist(`config/watchlist.toml`)의 모듈 전부
- `all` → 전체 CVE 중 고위험 Top 20 (`--all`)
- 첫 번째 단어 → `--module` (예: nginx, php, opnsense)
- 두 번째 단어가 숫자로 시작하면 → `--version` (예: 1.24.0)
- `days=N` → `--days N` (기간 고정, 자동 확장 안 함)
- `YYYY-MM-DD` → `--date`

예시:
- `/cve` → watchlist 전체
- `/cve nginx` → nginx, 최근 30일부터 결과가 모자라면 90일·365일로 확장
- `/cve nginx 1.24.0` → nginx 1.24.0 에 영향 있는 CVE 만
- `/cve php days=90` → php, 최근 90일 고정
- `/cve all` → 최근 30일 전체 CVE 중 Top 20

## 실행 순서

1. `$ARGUMENTS`를 파싱한다.
2. 프로젝트 루트에서 수집기를 실행한다. API 키(`.env` 의 `NVD_API_KEY`)가 없으면 새 NVD 요청 사이에 6.5초씩 쉬어서 몇 분 걸릴 수 있으니 timeout 을 넉넉히(10분) 준다. NVD 응답은 6시간 캐시되므로 같은 날 다시 돌리면 빠르다. 최신 데이터를 강제로 받으려면 `--no-cache`. `all` 은 수만 건을 받으므로 백그라운드로 실행한다.
   ```bash
   python -m pipeline.collect_cve --module nginx --version 1.24.0
   ```
3. 출력된 저장 경로의 `output/cve/YYYY-MM-DD-<라벨>.json`을 읽는다.
4. 아래 **출력 형식**으로 같은 이름의 `.md` 파일을 만든다 (`output/cve/YYYY-MM-DD-<라벨>.md`).
5. 터미널에는 모듈별 등급 건수와 S·A 등급 CVE ID 만 짧게 출력하고 md 경로를 알려준다.

## 작성 규칙

- 점수·날짜·KEV·EPSS·PoC 값은 JSON 그대로 쓴다. 값이 `null` 이면 `-` 로 적고, 추측해서 채우지 않는다.
- 순서는 JSON `items` 순서를 바꾸지 않는다. 수집기가 등급 순으로 놓고, 같은 등급 안에서는 위험 신호가 강한 것부터 정렬해 둔다 (S: 랜섬웨어 → KEV 등재일 최신순 / A: EPSS 높은 순 → CVSS+PoC 는 최신순 / B: CVSS 높은 순 / C: 최신순).
- 영향 버전은 `affected` 표기(`≤`, `<`)를 그대로 쓴다. `< 1.31.7` 을 `~1.31.6` 처럼 바꿔 쓰지 않는다.
- 요약은 `description` 을 한국어 한 줄(표) / 2~3문장(상세)로 옮긴다. 설명에 없는 공격 시나리오를 덧붙이지 않는다.
- `match_quality` 가 `"keyword"` 면 맨 위에 "⚠ modules.toml 에 없는 모듈이라 제품명 키워드로 찾았습니다. 다른 제품이 섞였을 수 있습니다." 를 적는다.
- `version_affected` 가 `null` 이면 "버전 확인 필요", `true` 면 "해당".
- `nvd_status` 가 `"Awaiting Analysis"`, `"Received"` 이면 CVSS 옆에 `(CNA)` 처럼 점수 출처가 NVD 가 아님을 표시한다 (`cvss.source` 참고).

## 출력 형식

```markdown
# CVE 리포트 — {모듈} {버전} (YYYY-MM-DD)

> 조회 기간: 최근 {window_days}일 · 매칭 {total_matched}건 · 등급 S {n} / A {n} / B {n} / C {n}

### 등급 기준
| 등급 | 조건 |
|---|---|
| S | CISA KEV 등재, 또는 CISA SSVC 에서 실제 악용 확인 |
| A | EPSS ≥ {epss_high×100}%, 또는 CVSS ≥ {cvss_critical} 이면서 공개 PoC 있음 |
| B | CVSS ≥ {cvss_high} |
| C | 그 외 |

## Top {N}

| # | 등급 | CVE | 공개일 | CVSS | EPSS | KEV | PoC | 영향 버전 | 요약 |
|---|---|---|---|---|---|---|---|---|---|
| 1 | A | [CVE-…](nvd_url) | 2026-10-14 | 9.2 | 0.8% | - | ✔ | 1.31.0 ≤ v < 1.31.7 | 한 줄 요약 |

(버전을 지정했으면 "영향 버전" 앞에 "버전 영향" 열을 추가한다.)

## S·A 등급 상세

### CVE-… (A)
- 등급 근거: {reasons}
- 설명: 2~3문장
- 영향 버전: {affected}
- 약점 유형: {cwe}
- PoC: 링크 목록
- 조치·참고: references 링크 (태그 표시)

## 관련 구성요소   ← components 가 있을 때만
### freebsd (최근 N일, 매칭 M건)
| 등급 | CVE | 공개일 | CVSS | 요약 |
```

watchlist 모드는 모듈마다 위 구조를 `# ` 대신 `## {모듈}` 섹션으로 반복하고, 맨 위에 모듈별 S/A 건수 요약표를 둔다.

`all` 모드는 실제 악용(S) CVE 가 기간 안에 수십 건이라 JSON 이 두 목록으로 나뉘어 있다. md 도 두 섹션으로 쓴다:

```markdown
## 실제 악용 중 ({exploited_total}건 중 {len(exploited)}건)
| # | CVE | 제품(요약에서) | KEV 등재일 | 랜섬웨어 | CVSS | 한 줄 요약 |

## 악용 확인 전 고위험 Top {N}
(위 Top 표와 같은 형식, items 사용)
```
