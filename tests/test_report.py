from apkspider.report import Finding, build_report


def test_report_serialization():
    finding = Finding(
        finding_id="TEST",
        title="Test Finding",
        description="Description",
        evidence="redacted",
        impacted_files=["file.txt"],
        severity_score=5.0,
        severity_label="medium",
        rationale="rationale",
        confidence="medium",
        category="Secrets",
        detection_type="content_match",
        references=["https://example.com"],
        masvs=["MSTG-STORAGE-2"],
        cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    )
    report = build_report(
        tool="APKSpider",
        tool_version="0.1.0",
        target="com.example",
        findings=[finding],
        pattern_meta={"version": "1.0", "sources": []},
    )
    payload = report.to_json()
    assert "findings" in payload
    assert "metadata" in payload
