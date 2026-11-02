from datetime import timedelta

from pipeline import collect_news
from pipeline.collectors import rss
from pipeline.common import now_kst

RSS_SAMPLE = """<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0" xmlns:dc="http://purl.org/dc/elements/1.1/"><channel>
<item>
  <title><![CDATA[ 다우기술 제품 보안 업데이트 권고 ]]></title>
  <link><![CDATA[ https://www.boho.or.kr/kr/bbs/view.do?nttId=1 ]]></link>
  <pubDate><![CDATA[ 2026-10-30 ]]></pubDate>
</item>
<item>
  <title>Hackers exploit CVE-2026-1234 in Ivanti</title>
  <link>https://example.com/a?utm_source=rss</link>
  <pubDate>Sat, 31 Oct 2026 12:00:00 +0000</pubDate>
  <description><![CDATA[<p>Attackers &amp; friends <b>chain</b> flaws.</p>]]></description>
</item>
</channel></rss>"""

ATOM_SAMPLE = """<?xml version="1.0"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>Atom title</title>
    <link rel="alternate" href="https://example.com/atom"/>
    <updated>2026-10-31T01:00:00Z</updated>
    <summary>hello</summary>
  </entry>
</feed>"""


def test_parse_rss_handles_cdata_html_and_date_only():
    entries = rss.parse_feed(RSS_SAMPLE.encode())
    assert entries[0]["title"] == "다우기술 제품 보안 업데이트 권고"
    assert entries[0]["url"] == "https://www.boho.or.kr/kr/bbs/view.do?nttId=1"
    # 날짜만 있으면 그날 끝(KST)으로 본다
    assert entries[0]["published"].isoformat() == "2026-10-30T23:59:59+09:00"
    assert entries[1]["summary"] == "Attackers & friends chain flaws."
    assert entries[1]["published"].isoformat() == "2026-10-31T21:00:00+09:00"


def test_clean_text_strips_feed_boilerplate():
    text = "Court sentenced a hacker. The post Syrian Hacker Gets Prison appeared first on SecurityWeek ."
    assert rss.clean_text(text) == "Court sentenced a hacker."
    assert rss.clean_text("Researchers found a flaw. [...]") == "Researchers found a flaw."


def test_parse_atom():
    [e] = rss.parse_feed(ATOM_SAMPLE.encode())
    assert e["url"] == "https://example.com/atom"
    assert e["published"].hour == 10  # 01:00Z → 10:00 KST


def test_canonical_url_strips_tracking_and_fragment():
    assert collect_news.canonical_url("HTTPS://Example.com/a/?utm_source=rss&id=3#top") == "https://example.com/a?id=3"


def _item(title, source, lang="en", url=None, published="2026-10-31T10:00:00+09:00"):
    return {
        "id": collect_news.item_id(url or f"https://{source}.com/{title}"),
        "title": title, "url": url or f"https://{source}.com/{title}", "source": source,
        "region": "해외" if lang == "en" else "국내", "lang": lang, "kind": "news",
        "published": published, "summary": "", "cve_ids": [],
    }


def test_cluster_merges_same_story_across_sources():
    items = [
        _item("Chainalysis confirms intrusion into internal tools", "thn"),
        _item("Chainalysis confirms intrusion into its internal tools", "bleeping"),
        _item("New ransomware strain targets VMware ESXi", "record"),
    ]
    clusters = collect_news.cluster(items)
    assert len(clusters) == 2
    assert clusters[0]["coverage"] == 2
    assert clusters[0]["also"][0]["source"] == "bleeping"


def _sitem(title, source, summary, lang="en"):
    return {**_item(title, source, lang=lang), "summary": summary}


def test_cluster_merges_differently_worded_titles_by_shared_entities():
    items = [
        _sitem('Chainalysis discloses data breach from "offensive agentic techniques"', "bleeping",
               "Blockchain analytics firm Chainalysis disclosed a data breach after attackers accessed internal tools."),
        _sitem("Chainalysis Confirms Intrusion Into Internal Tools and Exposure of Customer Identity Data", "thn",
               "American blockchain analysis firm Chainalysis said an external actor accessed customer data."),
        _sitem("현대이지웰 해킹으로 고객 개인정보 유출…이름·생년월일·아이디·주소 등 7개 항목", "dailysecu",
               "기업복지 서비스 현대이지웰에서 외부 해킹으로 회원정보 조회 API 를 통해 이름, 생년월일 등이 유출됐다.",
               lang="ko"),
        _sitem("340만명 사용 복지포인트 쇼핑몰 ‘현대이지웰’, 해킹으로 개인정보 유출", "boannews",
               "복지포인트 쇼핑몰 현대이지웰이 해킹으로 회원정보가 유출됐다. 이름 생년월일 성별 휴대폰번호.", lang="ko"),
    ]
    clusters = collect_news.cluster(items)
    assert [c["coverage"] for c in clusters] == [2, 2]


def test_cluster_keeps_apart_stories_sharing_one_word():
    items = [
        _sitem("Critical Linux kernel flaw allows remote root attacks on MPTCP servers", "bleeping",
               "Researchers developed an exploit for a Linux kernel vulnerability in Multipath TCP listeners."),
        _sitem("In Other News: Anthropic Breach Dispute, UEFI Flaw Hits Most Servers", "securityweek",
               "Noteworthy stories: Iran eyed in military freezer hacks, Copenhagen University breach."),
        _sitem("폴리마켓 해킹으로 이용자 가상자산 탈취…390만 달러 피해 보상 발표", "dailysecu",
               "예측시장 플랫폼 폴리마켓이 외부 서비스 공급업체를 통한 해킹으로 가상자산을 탈취당했다.", lang="ko"),
        _sitem("바이낸스 해킹으로 가상자산 63억 달러 탈취…북한 해커조직 배후 지목", "dailysecu",
               "세계 최대 가상자산 거래소 바이낸스가 대규모 해킹 공격을 받았다.", lang="ko"),
    ]
    assert len(collect_news.cluster(items)) == 4


def test_cluster_does_not_merge_across_languages():
    items = [_item("Binance hack FBI", "thn"), _item("Binance hack FBI", "boan", lang="ko")]
    assert len(collect_news.cluster(items)) == 2


def test_collect_filters_window_and_marks_seen(tmp_path, monkeypatch):
    now = now_kst()
    fresh = (now - timedelta(hours=2)).isoformat()
    old = (now - timedelta(days=3)).isoformat()
    sources = [{"name": "A", "url": "u", "region": "해외", "lang": "en"}]

    def fake_fetch_all(srcs):
        return ([_item("fresh story", "A", published=fresh), _item("old story", "A", published=old)],
                [{"name": "A", "count": 2, "error": None}])

    monkeypatch.setattr(collect_news, "load_toml", lambda name: {"sources": sources})
    monkeypatch.setattr(collect_news, "fetch_all", fake_fetch_all)
    monkeypatch.setattr(collect_news, "SEEN_PATH", tmp_path / "seen.json")

    first = collect_news.collect(timedelta(hours=24), "2026-10-31")
    assert [i["title"] for i in first["items"]] == ["fresh story"]
    assert first["items"][0]["new"] is True

    # 같은 날 다시 돌려도(스케줄러 + 수동 실행) 새 기사로 남는다
    again = collect_news.collect(timedelta(hours=24), "2026-10-31")
    assert again["items"][0]["new"] is True

    next_day = collect_news.collect(timedelta(hours=24), "2026-11-01")
    assert next_day["items"][0]["new"] is False
