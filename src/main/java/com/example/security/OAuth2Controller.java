package com.example.security;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import java.util.Map;

@RestController
@RequestMapping("/api/oauth2")
public class OAuth2Controller {

    @GetMapping("/user")
    public ResponseEntity<?> getOAuth2User(@AuthenticationPrincipal OAuth2User principal) {
        if (principal == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        }

        return ResponseEntity.ok(Map.of(
            "message", "OAuth2 - User profile",
            "name", principal.getAttribute("name"),
            "email", principal.getAttribute("email"),
            "provider", getProvider(principal),
            "attributes", principal.getAttributes()
        ));
    }

    @GetMapping("/profile")
    public ResponseEntity<?> getProfile(@AuthenticationPrincipal OAuth2User principal) {
        if (principal == null) {
            return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
        }

        return ResponseEntity.ok(Map.of(
            "message", "OAuth2 - User profile",
            "id", principal.getAttribute("id"),
            "name", principal.getAttribute("name"),
            "email", principal.getAttribute("email"),
            "avatar", getAvatarUrl(principal),
            "provider", getProvider(principal)
        ));
    }

    private String getProvider(OAuth2User principal) {
        // Determine provider based on attributes
        if (principal.getAttribute("login") != null) {
            return "github";
        } else if (principal.getAttribute("sub") != null) {
            return "google";
        }
        return "unknown";
    }

    private String getAvatarUrl(OAuth2User principal) {
        String provider = getProvider(principal);
        if ("github".equals(provider)) {
            return principal.getAttribute("avatar_url");
        } else if ("google".equals(provider)) {
            return principal.getAttribute("picture");
        }
        return null;
    }
}