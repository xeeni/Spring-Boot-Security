package com.example.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

public class RateLimitingFilter extends OncePerRequestFilter {

    private final RateLimitService rateLimitService;
    private final RateLimitConfig config;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public RateLimitingFilter(RateLimitService rateLimitService, RateLimitConfig config) {
        this.rateLimitService = rateLimitService;
        this.config = config;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        if (!config.isEnabled() || isExcludedPath(request.getRequestURI())) {
            filterChain.doFilter(request, response);
            return;
        }
        
        String clientId = getClientIdentifier(request);
        
        if (!rateLimitService.isAllowed(clientId)) {
            handleRateLimitExceeded(request, response, clientId);
            return;
        }
        
        // Add rate limit headers
        addRateLimitHeaders(response, clientId);
        
        filterChain.doFilter(request, response);
    }

    private String getClientIdentifier(HttpServletRequest request) {
        // Use IP address as identifier (in production, consider user ID)
        return request.getRemoteAddr();
    }

    private boolean isExcludedPath(String requestURI) {
        for (String excludedPath : config.getExcludedPaths()) {
            if (pathMatcher.match(excludedPath, requestURI)) {
                return true;
            }
        }
        return false;
    }

    private void handleRateLimitExceeded(HttpServletRequest request, HttpServletResponse response, String clientId) throws IOException {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType("application/json");
        
        long resetTime = rateLimitService.getResetTime(clientId);
        long retryAfter = (resetTime - System.currentTimeMillis()) / 1000;
        
        response.setHeader("Retry-After", String.valueOf(Math.max(1, retryAfter)));
        response.setHeader("X-RateLimit-Limit", String.valueOf(config.getMaxRequests()));
        response.setHeader("X-RateLimit-Remaining", "0");
        response.setHeader("X-RateLimit-Reset", String.valueOf(resetTime / 1000));
        
        String errorMessage = String.format(
            "{\"error\":\"Rate limit exceeded. Max %d requests per %d minute(s). Try again in %d seconds.\"}",
            config.getMaxRequests(), config.getTimeWindowMinutes(), retryAfter
        );
        
        response.getWriter().write(errorMessage);
    }

    private void addRateLimitHeaders(HttpServletResponse response, String clientId) {
        response.setHeader("X-RateLimit-Limit", String.valueOf(config.getMaxRequests()));
        response.setHeader("X-RateLimit-Remaining", String.valueOf(rateLimitService.getRemainingRequests(clientId)));
        response.setHeader("X-RateLimit-Reset", String.valueOf(rateLimitService.getResetTime(clientId) / 1000));
    }
}