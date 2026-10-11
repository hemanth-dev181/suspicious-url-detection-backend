package com.suspiciousurl.suspicious_url_system;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@CrossOrigin(origins = {
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://suspicious-url-reporting-system.vercel.app"
})
@RestController
public class UrlReportController {

    private final UrlReportService reportService;

    public UrlReportController(UrlReportService reportService) {
        this.reportService = reportService;
    }

    @PostMapping({"/api/urls/report", "/report"})
    public ResponseEntity<?> reportUrl(@RequestBody Map<String, String> request) {
        String url = request.get("url");
        String reason = request.get("reason");

        if (url == null || url.trim().isEmpty() || reason == null || reason.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(
                Map.of("message", "Both URL and reason are required.")
            );
        }

        if (url.length() > 2048 || reason.length() > 500) {
            return ResponseEntity.badRequest().body(
                Map.of("message", "Input limit exceeded: URL must be <= 2048 chars, reason <= 500 chars.")
            );
        }

        UrlReport savedReport = reportService.saveReport(url, reason);

        return ResponseEntity.status(HttpStatus.CREATED).body(
            Map.of(
                "message", "URL report submitted successfully.",
                "reportId", savedReport.getId(),
                "url", savedReport.getUrl(),
                "reason", savedReport.getReason(),
                "status", savedReport.getStatus(),
                "reportedAt", savedReport.getReportedAt()
            )
        );
    }

    @GetMapping({"/api/urls/reports", "/reports", "/api/urls/report"})
    public ResponseEntity<List<UrlReport>> getReports() {
        List<UrlReport> reports = reportService.getAllReports();
        return ResponseEntity.ok(reports);
    }
}
