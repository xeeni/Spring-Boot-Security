package com.example.security;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
public class RateLimitStatusController {

    private final RateLimitConfig config;

    public RateLimitStatusController(RateLimitConfig config) {
        this.config = config;
    }

    @GetMapping("/api/rate-limit/config")
    public ResponseEntity<?> getRateLimitConfig() {
        return ResponseEntity.ok(Map.of(
            "enabled", config.isEnabled(),
            "maxRequests", config.getMaxRequests(),
            "timeWindowMinutes", config.getTimeWindowMinutes(),
            "excludedPaths", config.getExcludedPaths(),
            "message", "Current rate limiting configuration"
        ));
    }
}