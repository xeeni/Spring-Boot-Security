package com.example.security;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import javax.servlet.http.HttpServletRequest;
import java.util.Map;

@RestController
@RequestMapping("/api/debug")
public class DebugController {

    @GetMapping("/auth")
    public ResponseEntity<?> debugAuth(HttpServletRequest request, Authentication auth) {
        String authHeader = request.getHeader("Authorization");
        String apiKey = request.getHeader("X-API-Key");
        
        Authentication contextAuth = SecurityContextHolder.getContext().getAuthentication();
        
        return ResponseEntity.ok(Map.of(
            "authHeader", authHeader != null ? authHeader.substring(0, Math.min(20, authHeader.length())) + "..." : "null",
            "apiKey", apiKey != null ? apiKey : "null",
            "authFromParam", auth != null ? Map.of(
                "name", auth.getName(),
                "authorities", auth.getAuthorities(),
                "authenticated", auth.isAuthenticated()
            ) : "null",
            "authFromContext", contextAuth != null ? Map.of(
                "name", contextAuth.getName(),
                "authorities", contextAuth.getAuthorities(),
                "authenticated", contextAuth.isAuthenticated()
            ) : "null"
        ));
    }

    @GetMapping("/jwt-test")
    public ResponseEntity<?> jwtTest(Authentication auth) {
        if (auth == null) {
            return ResponseEntity.status(401).body(Map.of("error", "No authentication found"));
        }
        
        return ResponseEntity.ok(Map.of(
            "message", "JWT authentication working",
            "user", auth.getName(),
            "authorities", auth.getAuthorities(),
            "authenticated", auth.isAuthenticated()
        ));
    }
}