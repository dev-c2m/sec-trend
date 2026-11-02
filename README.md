# sec-trend

![Python](https://img.shields.io/badge/python-3.11%2B-blue) ![License](https://img.shields.io/badge/license-MIT-green)

국내·해외 보안 뉴스와 CVE 취약점을 수집해 한국어 리포트(md)로 정리하는 Claude Code 도구입니다.

- **보안 뉴스**: 국내·해외 보안 매체의 소식을 모아 카테고리별 주요 20개로 요약합니다.
- **CVE**: 실제 악용 여부, 악용 확률, 공개 공격 코드, 심각도를 함께 보고 위험한 취약점부터 정리합니다. nginx, php 처럼 원하는 모듈만 골라 볼 수 있습니다.

## 설치

Python 3.11 이상이 필요합니다.

```bash
git clone https://github.com/dev-c2m/sec-trend.git
cd sec-trend
```

Claude Code 에서 이 폴더를 열면 `/secnews`, `/cve` 명령어를 사용할 수 있습니다. 따로 가입하거나 키를 발급받지 않아도 바로 사용할 수 있습니다.

## 사용법

### 보안 뉴스

```
/secnews              # 최근 24시간
/secnews 3d           # 최근 3일
/secnews 1w new       # 최근 1주 중 오늘 처음 본 기사만
```

### CVE

```
/cve                  # watchlist 에 등록한 모듈 전부 (기본: nginx, php, opnsense)
/cve nginx            # nginx 의 고위험·최신 CVE Top 20
/cve nginx 1.30.5     # nginx 1.30.5 에 영향 있는 CVE 만
/cve php days=90      # 최근 90일로 기간 고정
/cve all              # 최근 30일 전체 CVE 중 고위험 목록
```

결과는 `output/news/`, `output/cve/` 폴더에 md 파일로 저장됩니다.

## 결과 예시

- [보안 뉴스 다이제스트 (2026-10-31)](examples/secnews-2026-10-31.md)
- [CVE 리포트: nginx (2026-10-31)](examples/cve-nginx-2026-10-31.md)

## 리포트 읽는 법

### 보안 뉴스 카테고리

| 카테고리 | 내용 |
|---|---|
| 침해사고·유출 | 해킹 피해, 개인정보 유출 |
| 위협 동향 | 랜섬웨어 조직, APT, 피싱·악성코드 캠페인 |
| 취약점·패치 | 제로데이, 긴급 패치, 보안 업데이트 권고 |
| 솔루션·제품 | 신규 보안 제품·기능, 오픈소스 도구 |
| 정책·업계 | 규제, 수사·판결, 인수합병, 투자 |

여러 매체가 다룬 소식일수록 위에 놓이며, 해외 기사는 한국어로 번역해 요약합니다.

### CVE 위험도 등급

| 등급 | 의미 | 조건 |
|---|---|---|
| **S** | 실제 악용 중 | CISA KEV 등재, 또는 CISA 가 실제 악용을 확인 |
| **A** | 악용 가능성 높음 | 악용 확률(EPSS) 10% 이상, 또는 CVSS 9.0 이상이면서 공개 공격 코드(PoC) 있음 |
| **B** | 심각도 높음 | CVSS 7.0 이상 |
| **C** | 그 외 | |

리포트의 결과는 참고용입니다. 패치·대응 여부는 리포트에 링크된 벤더 권고문으로 확인해 주세요.

## 설정

`config/` 폴더의 파일을 수정해 바꿀 수 있습니다.

| 파일 | 내용 |
|---|---|
| `sources.toml` | 뉴스를 가져올 매체 목록 |
| `modules.toml` | `/cve` 로 조회할 수 있는 모듈 목록 |
| `watchlist.toml` | 인자 없이 `/cve` 를 실행했을 때 점검할 모듈과 버전 |
| `scoring.toml` | 등급 기준값, 결과 개수 |

### 모듈 추가

`modules.toml` 에 아래처럼 추가하면 `/cve tomcat` 으로 조회할 수 있습니다.

```toml
[modules.tomcat]
keyword = "tomcat"
cpes = ["apache:tomcat"]
products = ["apache tomcat"]
```

`cpes` 는 NVD 가 제품을 구분하는 이름(`제조사:제품`)입니다. [NVD CPE 검색](https://nvd.nist.gov/products/cpe/search)에서 찾을 수 있습니다.

### NVD 와 API 키 (선택)

`/cve` 는 CVE 목록, 설명, CVSS 점수, 영향 버전을 미국 NIST 의 취약점 데이터베이스인 [NVD](https://nvd.nist.gov/) 에서 받아 옵니다. 모듈별 조회와 버전 필터가 모두 이 데이터로 동작하기 때문에 NVD 는 `/cve` 의 기본 데이터 소스입니다.

NVD 는 **API 키 없이 사용할 수 있습니다.** 다만 키가 없으면 요청 속도가 제한되어 처음 조회할 때 시간이 걸립니다. 같은 날 다시 조회하면 저장해 둔 결과를 써서 몇 초 안에 끝납니다.

| 작업 | 키 없음 (처음) | 키 있음 (처음) | 같은 날 다시 |
|---|---|---|---|
| `/cve nginx` | 약 30초 | 약 5초 | 몇 초 |
| `/cve` (watchlist 3개) | 약 3분 | 약 30초 | 몇 초 |
| `/cve all` | 약 2분 | 약 1분 | 몇 초 |

속도를 높이고 싶다면 [무료로 발급](https://nvd.nist.gov/developers/request-an-api-key)받은 키를 프로젝트 폴더의 `.env` 파일에 `NVD_API_KEY=발급받은키` 로 넣으면 됩니다. 키가 있어도 없어도 결과는 같습니다.

## 라이선스

[MIT](LICENSE)
