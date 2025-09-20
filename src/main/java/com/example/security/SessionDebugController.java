package com.example.security;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.util.Map;

@RestController
@RequestMapping("/api/debug")
public class SessionDebugController {

    @GetMapping("/session")
    public ResponseEntity<?> getSessionInfo(HttpServletRequest request, Authentication auth) {
        HttpSession session = request.getSession(false);
        
        if (session == null) {
            return ResponseEntity.ok(Map.of("message", "No session found"));
        }

        return ResponseEntity.ok(Map.of(
            "sessionId", session.getId(),
            "creationTime", session.getCreationTime(),
            "lastAccessedTime", session.getLastAccessedTime(),
            "maxInactiveInterval", session.getMaxInactiveInterval(),
            "isNew", session.isNew(),
            "authenticated", auth != null,
            "authType", auth != null ? auth.getClass().getSimpleName() : "None",
            "principal", auth != null ? auth.getPrincipal().getClass().getSimpleName() : "None"
        ));
    }

    @GetMapping("/oauth2-session")
    public ResponseEntity<?> getOAuth2SessionDetails(HttpServletRequest request, Authentication auth) {
        HttpSession session = request.getSession(false);
        
        if (session == null || auth == null) {
            return ResponseEntity.ok(Map.of("message", "No OAuth2 session found"));
        }

        if (auth.getPrincipal() instanceof OAuth2User) {
            OAuth2User oauth2User = (OAuth2User) auth.getPrincipal();
            return ResponseEntity.ok(Map.of(
                "sessionId", session.getId(),
                "oauth2Provider", getProvider(oauth2User),
                "userAttributes", oauth2User.getAttributes(),
                "authorities", auth.getAuthorities(),
                "sessionStorage", "HTTP_SESSION_MEMORY"
            ));
        }

        return ResponseEntity.ok(Map.of("message", "Not an OAuth2 session"));
    }

    private String getProvider(OAuth2User principal) {
        if (principal.getAttribute("login") != null) {
            return "github";
        } else if (principal.getAttribute("sub") != null) {
            return "google";
        }
        return "unknown";
    }
}