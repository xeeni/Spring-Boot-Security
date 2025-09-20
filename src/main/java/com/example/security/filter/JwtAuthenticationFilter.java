/**
 * @author Zeenat Hussain
 */
package com.example.security.filter;

import com.example.security.util.JwtUtil;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;
import java.util.List;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        String requestURI = request.getRequestURI();
        
        // For JWT endpoints, clear any existing authentication to prevent cookie interference
        if (requestURI.startsWith("/api/jwt/")) {
            SecurityContextHolder.clearContext();
        }
        // For API key endpoints, also clear existing authentication
        else if (requestURI.startsWith("/api/key/")) {
            SecurityContextHolder.clearContext();
        }
        // Skip if already authenticated for other endpoints
        else if (SecurityContextHolder.getContext().getAuthentication() != null) {
            filterChain.doFilter(request, response);
            return;
        }
        
        String authHeader = request.getHeader("Authorization");
        String apiKey = request.getHeader("X-API-Key");
        
        try {
            // JWT Authentication
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                if (jwtUtil.isTokenValid(token)) {
                    String username = jwtUtil.extractUsername(token);
                    String role = jwtUtil.extractRole(token);
                    
                    var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role));
                    var authentication = new UsernamePasswordAuthenticationToken(username, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
            // API Key Authentication
            else if (apiKey != null) {
                if ("admin-key-123".equals(apiKey)) {
                    var authorities = List.of(new SimpleGrantedAuthority("ROLE_ADMIN"));
                    var authentication = new UsernamePasswordAuthenticationToken("api-admin", null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                } else if ("user-key-456".equals(apiKey)) {
                    var authorities = List.of(new SimpleGrantedAuthority("ROLE_USER"));
                    var authentication = new UsernamePasswordAuthenticationToken("api-user", null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        } catch (Exception e) {
            // Log the error but don't fail the request
            System.err.println("JWT Authentication error: " + e.getMessage());
        }
        
        filterChain.doFilter(request, response);
    }
}