/**
 * @author Zeenat Hussain
 */
package com.example.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
@RequestMapping("/api/public")
public class PublicController {

    @GetMapping("/info")
    public ResponseEntity<?> publicInfo() {
        return ResponseEntity.ok(Map.of(
            "message", "Public endpoint - No authentication required",
            "timestamp", System.currentTimeMillis(),
            "status", "success"
        ));
    }

    @GetMapping("/health")
    public ResponseEntity<?> health() {
        return ResponseEntity.ok(Map.of(
            "status", "UP",
            "message", "Application is running",
            "timestamp", System.currentTimeMillis()
        ));
    }

    @GetMapping("/test")
    public ResponseEntity<?> test() {
        return ResponseEntity.ok(Map.of(
            "message", "Public test endpoint working",
            "endpoint", "/api/public/test",
            "authentication", "none required",
            "timestamp", System.currentTimeMillis()
        ));
    }
}