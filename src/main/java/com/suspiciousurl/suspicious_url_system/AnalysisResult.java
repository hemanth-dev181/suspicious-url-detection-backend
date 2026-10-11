package com.suspiciousurl.suspicious_url_system;

import java.util.List;

public record AnalysisResult(
    String url,
    String verdict,
    String status,
    int riskScore,
    List<String> reasons,
    String educationalDisclaimer
) {}
