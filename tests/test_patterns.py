from apkspider.patterns import load_pattern_metadata, load_patterns


def test_load_patterns_has_entries():
    patterns = load_patterns()
    assert patterns, "Expected patterns to load"
    assert any(p.pattern_id == "PATH_DOTENV" for p in patterns)


def test_pattern_metadata_contains_version():
    meta = load_pattern_metadata()
    assert "version" in meta
    assert meta["version"] == "1.0"
