package com.suspiciousurl.suspicious_url_system;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class UrlCheckerServiceTest {

    private UrlCheckerService checkerService;

    @BeforeEach
    void setUp() {
        checkerService = new UrlCheckerService();
    }

    @Test
    void testSafeUrl() {
        AnalysisResult result = checkerService.analyzeUrl("https://example.com");
        assertEquals("SAFE", result.verdict());
        assertTrue(result.riskScore() < 35);
        assertFalse(result.reasons().isEmpty());
    }

    @Test
    void testIpBasedUrl() {
        AnalysisResult result = checkerService.analyzeUrl("http://192.168.1.1/login");
        assertEquals("SUSPICIOUS", result.verdict());
        assertTrue(result.riskScore() >= 35);
        assertTrue(result.reasons().stream().anyMatch(r -> r.contains("numerical IP address")));
    }

    @Test
    void testAtSymbolUrl() {
        AnalysisResult result = checkerService.analyzeUrl("https://google.com@evil-site.com/account");
        assertEquals("SUSPICIOUS", result.verdict());
        assertTrue(result.reasons().stream().anyMatch(r -> r.contains("@")));
    }

    @Test
    void testInvalidUrl() {
        AnalysisResult result = checkerService.analyzeUrl("not_a_valid_url");
        assertEquals("INVALID", result.verdict());
    }
}
