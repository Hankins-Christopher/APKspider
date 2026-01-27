from apkspider.scoring import label_from_score, score_from_base


def test_label_from_score():
    assert label_from_score(9.8) == "critical"
    assert label_from_score(8.0) == "high"
    assert label_from_score(5.0) == "medium"
    assert label_from_score(2.0) == "low"


def test_score_from_base_applies_confidence():
    result = score_from_base("high", "low")
    assert result.score < 8.8
    assert result.label in {"medium", "high"}
