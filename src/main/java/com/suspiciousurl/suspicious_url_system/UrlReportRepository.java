package com.suspiciousurl.suspicious_url_system;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UrlReportRepository extends JpaRepository<UrlReport, Long> {
    List<UrlReport> findAllByOrderByIdDesc();
}
