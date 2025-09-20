package com.example.security;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
public class OAuth2Controller {

    @GetMapping("/api/oauth2/user")
    public ResponseEntity<?> oauth2User(Authentication auth) {
        if (auth.getPrincipal() instanceof OAuth2User) {
            OAuth2User oauth2User = (OAuth2User) auth.getPrincipal();
            return ResponseEntity.ok(Map.of(
                "message", "OAuth2 - User info",
                "user", oauth2User.getName(),
                "email", oauth2User.getAttribute("email"),
                "provider", oauth2User.getAttribute("login") != null ? "GitHub" : "Google",
                "authorities", auth.getAuthorities()
            ));
        }
        return ResponseEntity.ok(Map.of(
            "message", "OAuth2 - User info",
            "user", auth.getName(),
            "authorities", auth.getAuthorities()
        ));
    }

    @GetMapping("/api/oauth2/profile")
    public ResponseEntity<?> oauth2Profile(Authentication auth) {
        if (auth.getPrincipal() instanceof OAuth2User) {
            OAuth2User oauth2User = (OAuth2User) auth.getPrincipal();
            return ResponseEntity.ok(Map.of(
                "message", "OAuth2 - User profile",
                "name", oauth2User.getAttribute("name"),
                "email", oauth2User.getAttribute("email"),
                "avatar", oauth2User.getAttribute("avatar_url"),
                "attributes", oauth2User.getAttributes()
            ));
        }
        return ResponseEntity.ok(Map.of(
            "message", "OAuth2 - User profile",
            "user", auth.getName()
        ));
    }
}