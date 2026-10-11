package com.suspiciousurl.suspicious_url_system;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "url_reports")
public class UrlReport {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(length = 2048, nullable = false)
    private String url;

    @Column(length = 500, nullable = false)
    private String reason;

    @Column(length = 50, nullable = false)
    private String status;

    @Column(nullable = false)
    private LocalDateTime reportedAt;

    public UrlReport() {
    }

    public UrlReport(String url, String reason) {
        this.url = url;
        this.reason = reason;
        this.status = "PENDING";
        this.reportedAt = LocalDateTime.now();
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public LocalDateTime getReportedAt() {
        return reportedAt;
    }

    public void setReportedAt(LocalDateTime reportedAt) {
        this.reportedAt = reportedAt;
    }
}
