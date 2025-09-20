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
                        // Public endpoints - MUST BE FIRST
                        .antMatchers("/api/public/**").permitAll()
                        .antMatchers("/api/auth/**").permitAll()
                        .antMatchers("/api/debug/**").permitAll()
                        .antMatchers("/api/rate-limit/public").permitAll()
                        .antMatchers("/h2-console/**").permitAll()
                        .antMatchers("/", "/login", "/register", "/web-login").permitAll()
                        .antMatchers("/css/**", "/js/**", "/images/**").permitAll()
                        .antMatchers("/oauth2/**", "/login/oauth2/**").permitAll()
                        .antMatchers("/dashboard", "/users").permitAll()

                        // OAuth2 endpoints
                        .antMatchers("/api/oauth2/**").authenticated()

                        // Rate limiting endpoints (except public)
                        .antMatchers("/api/rate-limit/**").hasAnyRole("USER", "ADMIN")

                        // Basic Auth endpoints
                        .antMatchers("/api/basic/**").hasAnyRole("USER", "ADMIN")

                        // JWT endpoints - Allow any authenticated user
                        .antMatchers("/api/jwt/**").authenticated()

                        // API Key endpoints
                        .antMatchers("/api/key/**").hasAnyRole("USER", "ADMIN")

                        // Role-based endpoints
                        .antMatchers("/api/role/user/**").hasAnyRole("USER", "ADMIN")
                        .antMatchers("/api/role/admin/**").hasRole("ADMIN")

                        // Method-level security endpoints
                        .antMatchers("/api/method/**").hasRole("ADMIN")

                        .anyRequest().authenticated()
                )
                .httpBasic(basic -> {})
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .defaultSuccessUrl("/dashboard", true)
                        .failureUrl("/login?error=true")
                )
                .addFilterBefore(new RateLimitingFilter(rateLimitService, rateLimitConfig), UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(new JwtAuthenticationFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class)
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout=true")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                );

        // H2 Console
        http.headers(headers -> headers.frameOptions().disable());

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}