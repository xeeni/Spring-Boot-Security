/**
 * @author Zeenat Hussain
 */
package com.example.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
public class SecureController {

    // 1. Basic Authentication Endpoints
    @GetMapping("/api/basic/user")
    public ResponseEntity<?> basicUser(Authentication auth) {
        return ResponseEntity.ok(Map.of(
            "message", "Basic Auth - User endpoint",
            "user", auth.getName(),
            "authorities", auth.getAuthorities()
        ));
    }

    @GetMapping("/api/basic/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> basicAdmin(Authentication auth) {
        return ResponseEntity.ok(Map.of(
            "message", "Basic Auth - Admin endpoint",
            "user", auth.getName()
        ));
    }

    // 2. JWT Authentication Endpoints
    @GetMapping("/api/jwt/user/profile")
    public ResponseEntity<?> jwtUserProfile(Authentication auth) {
        return ResponseEntity.ok(Map.of(
            "message", "JWT - User profile",
            "user", auth.getName(),
            "authorities", auth.getAuthorities()
        ));
    }

    @GetMapping("/api/jwt/admin/dashboard")
    public ResponseEntity<?> jwtAdminDashboard(Authentication auth) {
        return ResponseEntity.ok(Map.of(
            "message", "JWT - Admin dashboard",
            "user", auth.getName()
        ));
    }

    // 3. API Key Authentication Endpoints
    @GetMapping("/api/key/data")
    public ResponseEntity<?> apiKeyData(Authentication auth) {
        return ResponseEntity.ok(Map.of(
            "message", "API Key - Protected data",
            "user", auth.getName(),
            "authorities", auth.getAuthorities()
        ));
    }

    // 4. Role-based Endpoints
    @GetMapping("/api/role/user/info")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> userInfo(Authentication auth) {
        return ResponseEntity.ok(Map.of(
            "message", "Role-based - User info",
            "user", auth.getName()
        ));
    }

    @GetMapping("/api/role/admin/settings")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> adminSettings(Authentication auth) {
        return ResponseEntity.ok(Map.of(
            "message", "Role-based - Admin settings",
            "user", auth.getName()
        ));
    }

    // 5. Method-level Security
    @GetMapping("/api/method/sensitive")
    @PreAuthorize("hasRole('ADMIN') and authentication.name == 'admin'")
    public ResponseEntity<?> sensitiveData(Authentication auth) {
        return ResponseEntity.ok(Map.of(
            "message", "Method-level security - Sensitive data",
            "user", auth.getName()
        ));
    }



    // 6. Rate Limiting Test Endpoint
    @GetMapping("/api/rate-limit/secure")
    public ResponseEntity<?> rateLimitSecure(Authentication auth) {
        return ResponseEntity.ok(Map.of(
            "message", "Rate limited secure endpoint",
            "user", auth.getName(),
            "timestamp", System.currentTimeMillis()
        ));
    }
}