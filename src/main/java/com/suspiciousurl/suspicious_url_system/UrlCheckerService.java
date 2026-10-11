package com.suspiciousurl.suspicious_url_system;

import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

@Service
public class UrlCheckerService {

    private static final Pattern IPV4_PATTERN = Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}$");
    private static final Pattern SUSPICIOUS_KEYWORDS = Pattern.compile(
            ".*(login|signin|verify|verification|account|update|security|secure|banking|bank|password|credential|wallet|crypto|free|gift|reward|prize|claim|support|admin|recovery).*",
            Pattern.CASE_INSENSITIVE
    );

    private static final String DISCLAIMER =
            "Educational Notice: This system uses rule-based heuristic analysis. " +
            "A 'SAFE' verdict indicates no common deceptive patterns were found, but is not a guarantee against advanced threats. " +
            "Similarly, a 'SUSPICIOUS' verdict highlights risk signals for caution and further verification.";

    public AnalysisResult analyzeUrl(String rawUrl) {
        if (rawUrl == null || rawUrl.trim().isEmpty()) {
            return new AnalysisResult(
                    "",
                    "INVALID",
                    "INVALID",
                    0,
                    List.of("Please provide a valid URL to analyze."),
                    DISCLAIMER
            );
        }

        String input = rawUrl.trim();
        List<String> reasons = new ArrayList<>();
        int score = 0;

        // Decode URL to catch encoded attacks (e.g. %40 for @)
        String decodedInput;
        try {
            decodedInput = URLDecoder.decode(input, StandardCharsets.UTF_8);
        } catch (Exception e) {
            decodedInput = input;
        }

        String lower = decodedInput.toLowerCase(Locale.ROOT);

        // Check for dangerous or abnormal URL schemes
        if (lower.startsWith("javascript:") || lower.startsWith("data:") ||
            lower.startsWith("file:") || lower.startsWith("vbscript:")) {
            reasons.add("Suspicious URL scheme detected (" + input.split(":")[0] + "). Web links typically use HTTP or HTTPS.");
            return new AnalysisResult(
                    input,
                    "SUSPICIOUS",
                    "SUSPICIOUS",
                    95,
                    reasons,
                    DISCLAIMER
            );
        }

        // Validate HTTP / HTTPS presence
        if (!lower.startsWith("http://") && !lower.startsWith("https://")) {
            return new AnalysisResult(
                    input,
                    "INVALID",
                    "INVALID",
                    0,
                    List.of("URL must start with a valid protocol scheme (http:// or https://)."),
                    DISCLAIMER
            );
        }

        URI uri;
        try {
            uri = URI.create(decodedInput);
        } catch (IllegalArgumentException e) {
            return new AnalysisResult(
                    input,
                    "INVALID",
                    "INVALID",
                    0,
                    List.of("Malformed URL syntax: " + e.getMessage()),
                    DISCLAIMER
            );
        }

        String host = uri.getHost();
        if (host == null || host.trim().isEmpty()) {
            return new AnalysisResult(
                    input,
                    "INVALID",
                    "INVALID",
                    0,
                    List.of("Malformed URL: Host name is missing or invalid."),
                    DISCLAIMER
            );
        }

        // 1. IP-address-based host check
        if (IPV4_PATTERN.matcher(host).matches() || host.startsWith("[") || host.contains(":")) {
            score += 35;
            reasons.add("Host is a numerical IP address (" + host + ") instead of a domain name. Legitimate web services generally operate with registered domain names.");
        }

        // 2. Misleading '@' symbol check
        if (input.contains("@") || decodedInput.contains("@") || uri.getUserInfo() != null) {
            score += 35;
            reasons.add("URL contains an '@' symbol. Attackers frequently use '@' to mislead victims by masking the true destination host behind user authentication syntax.");
        }

        // 3. Excessive subdomains check
        String[] hostParts = host.split("\\.");
        if (hostParts.length > 4) {
            score += 20;
            reasons.add("Excessive number of subdomains detected (" + (hostParts.length - 2) + " subdomains). Phishing kits frequently chain subdomains to mimic legitimate brand names.");
        }

        // 4. Suspicious keywords check
        String hostAndPath = (host + (uri.getPath() != null ? uri.getPath() : "") + (uri.getQuery() != null ? uri.getQuery() : "")).toLowerCase(Locale.ROOT);
        if (SUSPICIOUS_KEYWORDS.matcher(hostAndPath).matches()) {
            score += 20;
            reasons.add("URL contains keywords often associated with credential harvesting or urgency lures (e.g., login, verify, account, secure, bank, free).");
        }

        // 5. Unusually long URL check
        if (input.length() > 100) {
            score += 15;
            reasons.add("URL length exceeds 100 characters (" + input.length() + " chars). Unusually long URLs are frequently used to conceal redirection parameters or token tracking.");
        }

        // 6. Non-standard port check
        int port = uri.getPort();
        if (port != -1 && port != 80 && port != 443 && port != 8080) {
            score += 15;
            reasons.add("URL targets an unusual non-standard port (:" + port + "). Legitimate web portals rarely require non-standard ports for public users.");
        }

        // 7. HTTPS Signal (one signal, not proof of safety)
        if (!lower.startsWith("https://")) {
            score += 15;
            reasons.add("URL uses unencrypted HTTP instead of HTTPS. Data is transmitted without encryption and vulnerable to intercept. (Note: HTTP alone does not necessarily mean malicious).");
        } else {
            reasons.add("URL uses HTTPS encryption. (Educational Note: HTTPS guarantees transit encryption, but does not prove the website content is trustworthy or free from phishing).");
        }

        score = Math.min(score, 100);
        String verdict = (score >= 35) ? "SUSPICIOUS" : "SAFE";

        if (reasons.isEmpty() || (score == 0 && reasons.size() == 1)) {
            reasons.add("No suspicious heuristic patterns detected by the basic security checks.");
        }

        return new AnalysisResult(
                input,
                verdict,
                verdict,
                score,
                reasons,
                DISCLAIMER
        );
    }
}
