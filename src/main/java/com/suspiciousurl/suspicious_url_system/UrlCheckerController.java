package com.suspiciousurl.suspicious_url_system;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = {
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://suspicious-url-reporting-system.vercel.app"
})
@RestController
public class UrlCheckerController {

    private final UrlCheckerService checkerService;

    public UrlCheckerController(UrlCheckerService checkerService) {
        this.checkerService = checkerService;
    }

    @GetMapping({"/api/urls/check", "/check"})
    public ResponseEntity<AnalysisResult> checkUrl(@RequestParam(name = "url", required = false) String url) {
        if (url == null || url.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(
                new AnalysisResult(
                    "",
                    "INVALID",
                    "INVALID",
                    0,
                    java.util.List.of("Please provide a URL parameter (?url=...) to analyze."),
                    "URL checking requires a valid URL parameter."
                )
            );
        }

        AnalysisResult result = checkerService.analyzeUrl(url);
        if ("INVALID".equals(result.verdict())) {
            return ResponseEntity.badRequest().body(result);
        }
        return ResponseEntity.ok(result);
    }
}
