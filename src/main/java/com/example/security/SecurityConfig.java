package com.example.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final JwtUtil jwtUtil;
    private final RateLimitService rateLimitService;
    private final RateLimitConfig rateLimitConfig;

    public SecurityConfig(JwtUtil jwtUtil, RateLimitService rateLimitService, RateLimitConfig rateLimitConfig) {
        this.jwtUtil = jwtUtil;
        this.rateLimitService = rateLimitService;
        this.rateLimitConfig = rateLimitConfig;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
            .authorizeHttpRequests(auth -> auth
                // Public endpoints
                .requestMatchers("/api/auth/**", "/api/public/**", "/api/rate-limit/public", "/h2-console/**", "/", "/login", "/register", "/css/**", "/js/**", "/oauth2/**", "/login/oauth2/**").permitAll()
                
                // OAuth2 endpoints
                .requestMatchers("/api/oauth2/**").authenticated()
                
                // Rate limiting endpoints
                .requestMatchers("/api/rate-limit/**").hasAnyRole("USER", "ADMIN")
                
                // Basic Auth endpoints
                .requestMatchers("/api/basic/**").hasAnyRole("USER", "ADMIN")
                
                // JWT endpoints
                .requestMatchers("/api/jwt/user/**").hasAnyRole("USER", "ADMIN")
                .requestMatchers("/api/jwt/admin/**").hasRole("ADMIN")
                
                // API Key endpoints
                .requestMatchers("/api/key/**").hasAnyRole("USER", "ADMIN")
                
                // Role-based endpoints
                .requestMatchers("/api/role/user/**").hasRole("USER")
                .requestMatchers("/api/role/admin/**").hasRole("ADMIN")
                
                .anyRequest().authenticated()
            )
            .httpBasic(basic -> {})
            .oauth2Login(oauth2 -> oauth2
                .loginPage("/login")
                .defaultSuccessUrl("/dashboard", true)
                .failureUrl("/login?error=true")
            )
            .addFilterBefore(new RateLimitingFilter(rateLimitService, rateLimitConfig), UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(new JwtAuthenticationFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);

        // H2 Console
        http.headers(headers -> headers.frameOptions().disable());

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}