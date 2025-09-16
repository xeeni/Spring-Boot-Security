package com.example.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
public class RateLimitController {

    @GetMapping("/api/rate-limit/test")
    public ResponseEntity<?> rateLimitTest(Authentication auth) {
        return ResponseEntity.ok(Map.of(
            "message", "Rate limiting test endpoint",
            "user", auth != null ? auth.getName() : "anonymous",
            "timestamp", System.currentTimeMillis()
        ));
    }

    @GetMapping("/api/rate-limit/public")
    public ResponseEntity<?> publicRateLimitTest() {
        return ResponseEntity.ok(Map.of(
            "message", "Public rate limiting test endpoint",
            "timestamp", System.currentTimeMillis()
        ));
    }

    @GetMapping("/api/rate-limit/status")
    public ResponseEntity<?> rateLimitStatus(HttpServletRequest request) {
        String clientId = request.getRemoteAddr();
        return ResponseEntity.ok(Map.of(
            "message", "Rate limit status",
            "clientId", clientId,
            "timestamp", System.currentTimeMillis()
        ));
    }
}