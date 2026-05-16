from unittest.mock import patch, MagicMock
from mcpmap.discover.shodan_source import shodan_targets, load_filters


def test_load_filters_has_categories():
    cats = load_filters()
    assert "core_mcp" in cats
    assert "endpoints" in cats
    assert any("Model Context Protocol" in q for q in cats["core_mcp"])


def test_shodan_targets_returns_empty_without_key(monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    assert shodan_targets("any") == []


def test_shodan_targets_dedupes_by_ip_port():
    fake_api = MagicMock()
    fake_api.search.return_value = {
        "matches": [
            {"ip_str": "1.2.3.4", "port": 8000},
            {"ip_str": "1.2.3.4", "port": 8000},  # dup
            {"ip_str": "1.2.3.5", "port": 8000},
        ]
    }
    with patch("mcpmap.discover.shodan_source.shodan.Shodan", return_value=fake_api):
        result = shodan_targets("test-key", queries=['"mcp"'])
    hosts = sorted({(t.host, t.port) for t in result})
    assert hosts == [("1.2.3.4", 8000), ("1.2.3.5", 8000)]
