import urllib.request

import pytest


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    """테스트가 실수로 외부 API 를 부르면 바로 실패시킨다."""
    def refuse(*args, **kwargs):
        raise RuntimeError("테스트에서 네트워크 호출이 일어났습니다. fetch 함수를 주입하거나 monkeypatch 하세요.")
    monkeypatch.setattr(urllib.request, "urlopen", refuse)
