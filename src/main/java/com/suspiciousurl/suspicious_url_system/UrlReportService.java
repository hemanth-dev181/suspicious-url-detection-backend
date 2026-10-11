package com.suspiciousurl.suspicious_url_system;

import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UrlReportService {

    private final UrlReportRepository repository;

    public UrlReportService(UrlReportRepository repository) {
        this.repository = repository;
    }

    public UrlReport saveReport(String url, String reason) {
        UrlReport report = new UrlReport(url.trim(), reason.trim());
        return repository.save(report);
    }

    public List<UrlReport> getAllReports() {
        return repository.findAllByOrderByIdDesc();
    }
}
