import sqlite3

from sysscan.config import AIConfig, load_config
from sysscan.describe import DescriptionPipeline
from sysscan.describe.ai import AIAnswer, build_user_message
from sysscan.envfile import load_env_files, parse_env
from sysscan.models import Action, Category, Change, TimeConfidence
from sysscan.normalize import normalize_name
from sysscan.store import Store
from sysscan.winutil import utcnow


def change(name, publisher=None, desc=None, cat=Category.DESKTOP_APP):
    return Change(category=cat, action=Action.INSTALLED, name=name, time=utcnow(),
                  confidence=TimeConfidence.EXACT, publisher=publisher, description=desc,
                  norm_name=normalize_name(name))


class Recorder:
    """Fake Claude: records what it was asked, answers from a table."""

    def __init__(self, answers):
        self.answers = answers
        self.requests = []

    def factory(self, *_):
        return self

    def describe(self, items):
        self.requests.append(items)
        return {it.id: self.answers[it.name] for it in items if it.name in self.answers}


# ----------------------------------------------------------------------------- .env

def test_parse_env_syntax():
    text = """
# comment
ANTHROPIC_API_KEY="sk-ant-123"
export SYSSCAN_AI=true
SYSSCAN_AI_MODEL=claude-haiku-4-5  # inline comment
EMPTY=
"""
    assert parse_env(text) == {"ANTHROPIC_API_KEY": "sk-ant-123", "SYSSCAN_AI": "true",
                               "SYSSCAN_AI_MODEL": "claude-haiku-4-5", "EMPTY": ""}


def test_env_file_loads_without_overriding_real_env(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("ANTHROPIC_API_KEY=from-file\nSYSSCAN_AI=on\n")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "from-shell")
    monkeypatch.setenv("SYSSCAN_AI", "")  # empty counts as unset; monkeypatch restores it afterwards
    assert load_env_files([env, tmp_path / "missing.env"]) == [env]
    import os

    assert os.environ["ANTHROPIC_API_KEY"] == "from-shell"
    assert os.environ["SYSSCAN_AI"] == "on"


def test_env_flag_overrides_config_file(tmp_path, monkeypatch):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text("[ai]\nenabled = false\n")
    monkeypatch.setenv("SYSSCAN_AI", "true")
    monkeypatch.setenv("SYSSCAN_AI_MAX_ITEMS", "20")
    cfg = load_config(cfg_file)
    assert cfg.ai.enabled and cfg.ai.max_items_per_run == 20
    monkeypatch.setenv("SYSSCAN_AI", "false")
    assert not load_config(cfg_file).ai.enabled


# ----------------------------------------------------------------------------- enrichment

def test_ai_fills_missing_publisher_and_description(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    fake = Recorder({
        "Mystery Tool": AIAnswer("A disk utility.", "Contoso", "high"),
        "Git for Windows": AIAnswer("ignored", "The Git Development Community", "high"),
    })
    known = change("Known App", publisher="Acme Inc.", desc="Edits photos and videos quickly")
    mystery = change("Mystery Tool")
    git = change("Git for Windows")  # rule gives the description; only the publisher is missing
    pipe = DescriptionPipeline(Store(":memory:"), AIConfig(enabled=True), use_ai=True, describer_factory=fake.factory)
    pipe.run([known, mystery, git])

    sent = {it.name: it.needs for batch in fake.requests for it in batch}
    assert "Known App" not in sent  # nothing missing -> not sent
    assert sent["Mystery Tool"] == ["description", "publisher"]
    assert sent["Git for Windows"] == ["publisher"]

    assert (mystery.description, mystery.description_source) == ("A disk utility.", "ai")
    assert (mystery.publisher, mystery.provider, mystery.publisher_source) == ("Contoso", "Contoso", "ai")
    assert git.description_source == "rule" and git.publisher_source == "ai"
    assert known.publisher_source is None and known.description_source == "publisher"
    assert any("Claude filled in" in m for m in pipe.messages)


def test_low_confidence_publisher_is_not_used_and_unknowns_are_not_resent(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    fake = Recorder({"Weird Thing": AIAnswer("Probably a helper tool.", "Guess Corp", "low")})
    store = Store(":memory:")
    c = change("Weird Thing")
    DescriptionPipeline(store, AIConfig(), use_ai=True, describer_factory=fake.factory).run([c])
    assert c.description_source == "ai-low" and c.provider == "Unknown"

    again = change("Weird Thing")
    DescriptionPipeline(store, AIConfig(), use_ai=True, describer_factory=fake.factory).run([again])
    assert len(fake.requests) == 1  # cached, including the "publisher unknown" answer
    assert again.description == "Probably a helper tool." and again.provider == "Unknown"


def test_ai_disabled_sends_nothing(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    fake = Recorder({})
    c = change("Mystery Tool")
    DescriptionPipeline(Store(":memory:"), AIConfig(), use_ai=False, describer_factory=fake.factory).run([c])
    assert fake.requests == [] and c.description_source == "none" and c.provider == "Unknown"


def test_missing_key_is_reported(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr("sysscan.describe.ai.get_api_key", lambda: None)
    pipe = DescriptionPipeline(Store(":memory:"), AIConfig(), use_ai=True)
    pipe.run([change("Mystery Tool")])
    assert any(".env" in m for m in pipe.messages)


def test_ollama_runs_without_api_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    class FakeOllama:
        def describe(self, items, web=False):
            assert web is False
            return {it.id: AIAnswer("A disk utility.", "Contoso", "high") for it in items}

    pipe = DescriptionPipeline(
        Store(":memory:"),
        AIConfig(provider="ollama", model="llama3.2"),
        use_ai=True,
        describer_factory=lambda _ai: FakeOllama(),
    )
    c = change("Mystery Tool")
    pipe.run([c])
    assert (c.description, c.description_source) == ("A disk utility.", "ai")
    assert (c.publisher, c.publisher_source) == ("Contoso", "ai")
    assert any("Ollama filled in" in m for m in pipe.messages)


def test_ollama_skips_web_search(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    calls: list[bool] = []

    class FakeOllama:
        def describe(self, items, web=False):
            calls.append(web)
            return {it.id: AIAnswer("Maybe a tool.", None, "low") for it in items}

    store = Store(":memory:")
    c = change("Weird Thing")
    pipe = DescriptionPipeline(
        store, AIConfig(provider="ollama", web=True), use_ai=True,
        describer_factory=lambda _ai: FakeOllama(),
    )
    pipe.run([c])
    assert calls == [False]
    assert c.description_source == "ai-low"
    assert any("Web search is only available with Claude" in m for m in pipe.messages)

    # Cached low-confidence answer would normally trigger a Claude web retry; Ollama must not.
    calls.clear()
    again = change("Weird Thing")
    pipe2 = DescriptionPipeline(
        store, AIConfig(provider="ollama", web=True), use_ai=True,
        describer_factory=lambda _ai: FakeOllama(),
    )
    pipe2.run([again])
    assert calls == []  # web-retry candidates are not re-sent on the plain pass
    assert any("Web search is only available with Claude" in m for m in pipe2.messages)
    assert again.description_source == "ai-low"


def test_provider_and_base_url_from_env(tmp_path, monkeypatch):
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text('[ai]\nenabled = true\nprovider = "claude"\n')
    monkeypatch.setenv("SYSSCAN_AI_PROVIDER", "ollama")
    monkeypatch.setenv("SYSSCAN_AI_MODEL", "qwen2.5")
    monkeypatch.setenv("SYSSCAN_AI_BASE_URL", "http://192.168.1.10:11434")
    cfg = load_config(cfg_file)
    assert cfg.ai.provider == "ollama"
    assert cfg.ai.model == "qwen2.5"
    assert cfg.ai.base_url == "http://192.168.1.10:11434"


def test_ollama_parse_chat_response():
    from sysscan.describe.ai import OllamaDescriber, parse_response

    text = 'Here you go:\n[{"id": 0, "description": "A text editor.", "publisher": "Microsoft", "confidence": "high"}]\n'
    ans = parse_response(text)[0]
    assert ans.description == "A text editor." and ans.publisher == "Microsoft"
    d = OllamaDescriber("llama3.2", "http://127.0.0.1:11434")
    assert d.provider == "ollama"


def test_prompt_lists_needed_fields():
    from sysscan.describe.ai import AIItem

    msg = build_user_message([AIItem(0, "X", None, "1.0", "Desktop apps", needs=["publisher"])])
    assert '"needs"' in msg and '"publisher"' in msg


def test_old_description_cache_is_migrated(tmp_path):
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE descriptions (norm_key TEXT PRIMARY KEY, description TEXT NOT NULL, "
                "source TEXT NOT NULL, model TEXT, created_at TEXT NOT NULL)")
    con.execute("INSERT INTO descriptions VALUES ('k', 'Old text', 'ai', 'm', '2026-01-01')")
    con.commit()
    con.close()
    store = Store(db)
    cached = store.get_description("k")
    assert cached.description == "Old text" and cached.publisher is None  # publisher never asked
