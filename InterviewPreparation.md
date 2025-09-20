# Spring Boot Security - Complete Interview Preparation Guide

## Core Security Concepts

### Q1: What's the difference between Authentication and Authorization?
**A:** 
- **Authentication**: Verifies identity (who you are) - login process
- **Authorization**: Determines permissions (what you can access) - access control
- **Example**: Login with username/password (authentication) → Access admin panel (authorization)

### Q2: Explain Spring Security Filter Chain
**A:** Ordered sequence of filters that process every request:
```
Request → SecurityContextPersistenceFilter → UsernamePasswordAuthenticationFilter → 
FilterSecurityInterceptor → Controller
```
Each filter can authenticate, authorize, or modify the request.

---

## Authentication Methods

### Q3: Compare Basic Auth vs JWT vs API Keys
**A:**

| Aspect | Basic Auth | JWT | API Keys |
|--------|------------|-----|----------|
| **State** | Stateless | Stateless | Stateless |
| **Storage** | None | Client-side | Client-side |
| **Expiration** | No | Yes | No (manual) |
| **Scalability** | Good | Excellent | Good |
| **Security** | Medium | High | Medium |
| **Use Case** | Internal APIs | Web/Mobile apps | Service-to-service |

### Q4: How does JWT work internally?
**A:** JWT has 3 parts: `Header.Payload.Signature`
```java
// Generation
String token = Jwts.builder()
    .subject("admin")
    .claim("role", "ADMIN")
    .issuedAt(new Date())
    .expiration(new Date(System.currentTimeMillis() + 86400000))
    .signWith(secretKey)
    .compact();

// Validation
Claims claims = Jwts.parser()
    .verifyWith(secretKey)
    .build()
    .parseSignedClaims(token)
    .getPayload();
```

### Q5: What are JWT security concerns?
**A:**
- **Token theft**: Store securely, use HTTPS
- **Secret key compromise**: Rotate keys regularly
- **Token size**: Larger than session IDs
- **Cannot revoke**: Use short expiration + refresh tokens
- **Replay attacks**: Include timestamp, use HTTPS

### Q6: How do you implement custom authentication in Spring Security?
**A:**
```java
@Component
public class CustomAuthenticationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, 
                                  HttpServletResponse response, 
                                  FilterChain filterChain) {
        String token = extractToken(request);
        if (isValidToken(token)) {
            Authentication auth = createAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        filterChain.doFilter(request, response);
    }
}
```

---

## OAuth2 Authentication

### Q7: What is OAuth2 and how does it work?
**A:** OAuth2 is an authorization framework that enables applications to obtain limited access to user accounts. It works by delegating user authentication to the service that hosts the user account.

**Flow:**
1. Client redirects user to authorization server
2. User authenticates with authorization server
3. Authorization server redirects back with authorization code
4. Client exchanges code for access token
5. Client uses access token to access protected resources

### Q8: How do you implement OAuth2 in Spring Boot?
**A:**
```java
// Add dependency
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-oauth2-client</artifactId>
</dependency>

// Configure in SecurityConfig
.oauth2Login(oauth2 -> oauth2
    .loginPage("/login")
    .defaultSuccessUrl("/dashboard", true)
    .failureUrl("/login?error=true")
)

// Handle OAuth2 user
@GetMapping("/api/oauth2/user")
public ResponseEntity<?> getUser(@AuthenticationPrincipal OAuth2User principal) {
    return ResponseEntity.ok(Map.of(
        "name", principal.getAttribute("name"),
        "email", principal.getAttribute("email")
    ));
}
```

### Q9: What's the difference between OAuth2 and JWT?
**A:**
- **OAuth2**: Authorization framework/protocol
- **JWT**: Token format that can be used with OAuth2
- **OAuth2**: Defines how to get tokens
- **JWT**: Defines token structure and validation
- **Can be combined**: OAuth2 can use JWT as access token format

---

## Authorization & Access Control

### Q10: Explain @PreAuthorize vs @PostAuthorize
**A:**
- **@PreAuthorize**: Checks before method execution
- **@PostAuthorize**: Checks after method execution (can access return value)
```java
@PreAuthorize("hasRole('ADMIN')")
public void deleteUser(Long id) { }

@PostAuthorize("returnObject.owner == authentication.name")
public Document getDocument(Long id) { }
```

### Q11: What's the difference between hasRole() and hasAuthority()?
**A:**
- **hasRole('ADMIN')**: Checks for "ROLE_ADMIN" authority (adds ROLE_ prefix)
- **hasAuthority('ROLE_ADMIN')**: Checks exact authority string
- **hasAuthority('READ')**: Checks for "READ" permission

### Q12: How do you implement method-level security?
**A:**
```java
@EnableMethodSecurity(prePostEnabled = true)
@Configuration
public class SecurityConfig {
    
    @PreAuthorize("hasRole('ADMIN') and authentication.name == 'admin'")
    public String sensitiveOperation() {
        return "Sensitive data";
    }
    
    @PreAuthorize("#userId == authentication.principal.id")
    public User getUserProfile(Long userId) {
        return userService.findById(userId);
    }
}
```

---

## Rate Limiting

### Q13: Why implement rate limiting?
**A:**
- **Prevent abuse**: Stop malicious attacks
- **Resource protection**: Avoid server overload
- **Fair usage**: Ensure equal access for all users
- **Cost control**: Limit expensive operations

### Q14: Explain different rate limiting algorithms
**A:**
1. **Fixed Window**: 10 requests per minute (resets at minute boundary)
2. **Sliding Window**: 10 requests in any 60-second period
3. **Token Bucket**: Refill tokens at fixed rate
4. **Leaky Bucket**: Process requests at steady rate

### Q15: How do you implement rate limiting in Spring Boot?
**A:**
```java
@Service
public class RateLimitService {
    private final ConcurrentHashMap<String, UserRequestInfo> requestCounts = new ConcurrentHashMap<>();
    
    public boolean isAllowed(String clientId) {
        long currentTime = System.currentTimeMillis();
        
        requestCounts.compute(clientId, (key, userInfo) -> {
            if (userInfo == null || isWindowExpired(userInfo, currentTime)) {
                return new UserRequestInfo(currentTime, new AtomicInteger(1));
            } else {
                userInfo.requestCount.incrementAndGet();
                return userInfo;
            }
        });
        
        return requestCounts.get(clientId).requestCount.get() <= maxRequests;
    }
}
```

### Q16: How do you handle rate limit exceeded scenarios?
**A:**
```java
if (!rateLimitService.isAllowed(clientId)) {
    response.setStatus(429); // Too Many Requests
    response.setHeader("Retry-After", "60");
    response.setHeader("X-RateLimit-Limit", "10");
    response.setHeader("X-RateLimit-Remaining", "0");
    response.setHeader("X-RateLimit-Reset", String.valueOf(resetTime));
    return; // Stop processing
}
```

---

## Security Configuration

### Q17: Explain SecurityFilterChain configuration
**A:**
```java
@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    return http
        .csrf(csrf -> csrf.disable())
        .sessionManagement(session -> 
            session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/public/**").permitAll()
            .requestMatchers("/api/admin/**").hasRole("ADMIN")
            .anyRequest().authenticated())
        .addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class)
        .build();
}
```

### Q18: How do you configure multiple authentication methods?
**A:**
```java
// In custom filter
if (authHeader != null && authHeader.startsWith("Bearer ")) {
    // JWT Authentication
    handleJwtAuth(request);
} else if (apiKey != null) {
    // API Key Authentication
    handleApiKeyAuth(request);
}
// Basic Auth handled by Spring Security's built-in filter
```

### Q19: What's the purpose of @EnableMethodSecurity?
**A:**
- Enables method-level security annotations
- `prePostEnabled = true`: Enables @PreAuthorize/@PostAuthorize
- `securedEnabled = true`: Enables @Secured
- `jsr250Enabled = true`: Enables @RolesAllowed

---

## Password Security

### Q20: Why use BCrypt for password hashing?
**A:**
- **Salt included**: Prevents rainbow table attacks
- **Adaptive**: Can increase rounds as hardware improves
- **Slow by design**: Makes brute force attacks impractical
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(12); // 12 rounds
}
```

### Q21: How do you implement custom UserDetailsService?
**A:**
```java
@Service
public class CustomUserDetailsService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String username) 
            throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        
        return org.springframework.security.core.userdetails.User.builder()
            .username(user.getUsername())
            .password(user.getPassword())
            .authorities("ROLE_" + user.getRole().name())
            .build();
    }
}
```

---

## Session Management

### Q22: What's the difference between stateless and stateful authentication?
**A:**
- **Stateless (JWT)**: No server-side session, token contains all info
- **Stateful (Session)**: Server stores user state, client has session ID
- **Scalability**: Stateless scales better (no session storage)
- **Security**: Stateful easier to revoke, stateless harder to invalidate

### Q23: How do you configure session management?
**A:**
```java
.sessionManagement(session -> session
    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)  // For JWT
    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) // For OAuth2
    .maximumSessions(1)  // Limit concurrent sessions
    .maxSessionsPreventsLogin(false)  // Allow new login, expire old
)
```

---

## Error Handling

### Q24: How do you handle authentication failures?
**A:**
```java
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, 
                        HttpServletResponse response,
                        AuthenticationException authException) {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write(
            "{\"error\":\"Unauthorized\",\"message\":\"" + 
            authException.getMessage() + "\"}"
        );
    }
}
```

### Q25: What are common Spring Security exceptions?
**A:**
- **BadCredentialsException**: Wrong username/password
- **UsernameNotFoundException**: User doesn't exist
- **AccountExpiredException**: Account expired
- **CredentialsExpiredException**: Password expired
- **DisabledException**: Account disabled
- **LockedException**: Account locked
- **AccessDeniedException**: Insufficient permissions

---

## Testing Security

### Q26: How do you test secured endpoints?
**A:**
```java
@SpringBootTest
@AutoConfigureTestMvc
class SecurityTest {
    
    @Test
    @WithMockUser(roles = "ADMIN")
    void adminEndpoint_WithAdminRole_Success() throws Exception {
        mockMvc.perform(get("/api/admin/data"))
            .andExpect(status().isOk());
    }
    
    @Test
    void protectedEndpoint_WithoutAuth_Unauthorized() throws Exception {
        mockMvc.perform(get("/api/protected"))
            .andExpect(status().isUnauthorized());
    }
}
```

### Q27: How do you test JWT authentication?
**A:**
```java
@Test
void jwtEndpoint_WithValidToken_Success() throws Exception {
    String token = jwtUtil.generateToken("admin", "ADMIN");
    
    mockMvc.perform(get("/api/jwt/data")
            .header("Authorization", "Bearer " + token))
        .andExpect(status().isOk());
}
```

---

## Performance & Scalability

### Q28: How does Spring Security impact performance?
**A:**
- **Filter Chain**: Each request goes through security filters
- **Password Hashing**: BCrypt is intentionally slow (good for security)
- **Session Storage**: Memory usage for stateful authentication
- **Database Queries**: UserDetailsService queries on each login
- **Optimization**: Use caching, connection pooling, stateless auth

### Q29: How do you optimize Spring Security performance?
**A:**
```java
// 1. Cache UserDetails
@Cacheable("users")
public UserDetails loadUserByUsername(String username) { }

// 2. Use stateless authentication
.sessionCreationPolicy(SessionCreationPolicy.STATELESS)

// 3. Optimize BCrypt rounds
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(10); // Lower rounds for better performance
}

// 4. Skip security for static resources
.requestMatchers("/css/**", "/js/**").permitAll()
```

---

## Advanced Topics

### Q30: What is CSRF and how does Spring Security handle it?
**A:**
- **CSRF**: Cross-Site Request Forgery attack
- **Protection**: Spring Security generates CSRF tokens
- **Stateless APIs**: Disable CSRF for REST APIs
- **Configuration**: `.csrf().disable()` for APIs, enabled for web forms

### Q31: How do you implement custom security filters?
**A:**
```java
public class CustomSecurityFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain filterChain) {
        // Custom security logic
        String customHeader = request.getHeader("X-Custom-Auth");
        if (isValid(customHeader)) {
            // Set authentication
            SecurityContextHolder.getContext().setAuthentication(auth);
        }
        filterChain.doFilter(request, response);
    }
}

// Add to security config
.addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class)
```

### Q32: What are the security best practices?
**A:**
1. **Use HTTPS**: Encrypt data in transit
2. **Strong passwords**: Enforce password policies
3. **Regular updates**: Keep dependencies updated
4. **Principle of least privilege**: Minimal required permissions
5. **Input validation**: Validate all user inputs
6. **Secure headers**: Use security headers (HSTS, CSP)
7. **Audit logging**: Log security events
8. **Rate limiting**: Prevent brute force attacks
9. **Token expiration**: Use short-lived tokens
10. **Secure storage**: Encrypt sensitive data at rest

---

## Summary

This guide covers all major Spring Security concepts implemented in the demo:
- **Authentication methods**: Basic, JWT, API Key, OAuth2
- **Authorization**: Role-based, method-level security
- **Rate limiting**: Request throttling and protection
- **Security configuration**: Filter chains, password encoding
- **Error handling**: Custom exception handling
- **Testing**: Security test strategies
- **Performance**: Optimization techniques
- **Best practices**: Security recommendations

Use this guide to prepare for Spring Security interviews and understand the complete security implementation in the demo application. {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        
        return org.springframework.security.core.userdetails.User.builder()
            .username(user.getUsername())
            .password(user.getPassword())
            .authorities(user.getRole().name())
            .build();
    }
}
```

---

## Error Handling & Security

### Q22: How do you handle authentication failures?
**A:**
```java
@ControllerAdvice
public class SecurityExceptionHandler {
    
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<?> handleAuthenticationException(AuthenticationException ex) {
        return ResponseEntity.status(401)
            .body(Map.of("error", "Authentication failed", "message", ex.getMessage()));
    }
    
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<?> handleAccessDeniedException(AccessDeniedException ex) {
        return ResponseEntity.status(403)
            .body(Map.of("error", "Access denied", "message", "Insufficient privileges"));
    }
}
```

### Q23: What security headers should you implement?
**A:**
```java
http.headers(headers -> headers
    .frameOptions().deny()
    .contentTypeOptions().and()
    .httpStrictTransportSecurity(hstsConfig -> hstsConfig
        .maxAgeInSeconds(31536000)
        .includeSubdomains(true))
    .and()
    .sessionManagement(session -> session
        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)));
```

---

## Advanced Topics

### Q24: How do you implement logout with JWT?
**A:**
**Client-side approach:**
```javascript
// Remove token from storage
localStorage.removeItem('jwt-token');
sessionStorage.removeItem('jwt-token');
```

**Server-side approach (Token Blacklist):**
```java
@Service
public class TokenBlacklistService {
    private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();
    
    public void blacklistToken(String token) {
        blacklistedTokens.add(token);
    }
    
    public boolean isBlacklisted(String token) {
        return blacklistedTokens.contains(token);
    }
}
```

### Q25: How do you implement refresh tokens?
**A:**
```java
@PostMapping("/refresh")
public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest request) {
    if (refreshTokenService.isValidRefreshToken(request.getRefreshToken())) {
        String newAccessToken = jwtUtil.generateAccessToken(user);
        String newRefreshToken = refreshTokenService.generateRefreshToken(user);
        
        return ResponseEntity.ok(new TokenResponse(newAccessToken, newRefreshToken));
    }
    return ResponseEntity.status(401).body("Invalid refresh token");
}
```

### Q26: How do you secure microservices communication?
**A:**
- **Service-to-service**: Use API keys or mutual TLS
- **Gateway pattern**: Authenticate at API gateway
- **JWT propagation**: Pass JWT between services
- **Service mesh**: Use Istio/Linkerd for security

### Q27: What's the difference between stateful and stateless authentication?
**A:**

| Aspect | Stateful (Sessions) | Stateless (JWT) |
|--------|-------------------|-----------------|
| **Storage** | Server-side | Client-side |
| **Scalability** | Limited | Excellent |
| **Memory** | Uses server memory | No server memory |
| **Logout** | Easy (destroy session) | Complex (blacklist) |
| **Security** | Session hijacking risk | Token theft risk |

---

## Testing Security

### Q28: How do you test secured endpoints?
**A:**
```java
@SpringBootTest
@AutoConfigureTestDatabase
class SecurityTest {
    
    @Test
    @WithMockUser(roles = "ADMIN")
    void testAdminEndpoint() {
        mockMvc.perform(get("/api/admin/data"))
            .andExpect(status().isOk());
    }
    
    @Test
    void testJwtAuthentication() {
        String token = jwtUtil.generateToken("admin", "ADMIN");
        
        mockMvc.perform(get("/api/jwt/profile")
                .header("Authorization", "Bearer " + token))
            .andExpected(status().isOk());
    }
    
    @Test
    void testRateLimit() {
        // Make 10 requests
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(get("/api/rate-limit/public"))
                .andExpect(status().isOk());
        }
        
        // 11th request should be rate limited
        mockMvc.perform(get("/api/rate-limit/public"))
            .andExpect(status().isTooManyRequests());
    }
}
```

---

## Performance & Optimization

### Q29: How do you optimize security performance?
**A:**
- **Cache user details**: Avoid repeated database queries
- **Efficient token validation**: Use fast algorithms
- **Connection pooling**: For database connections
- **Rate limiting**: Prevent resource exhaustion
```java
@Cacheable("users")
public UserDetails loadUserByUsername(String username) {
    return userRepository.findByUsername(username);
}
```

### Q30: How do you monitor security events?
**A:**
```java
@EventListener
public void handleAuthenticationSuccess(AuthenticationSuccessEvent event) {
    log.info("User {} authenticated successfully", event.getAuthentication().getName());
}

@EventListener
public void handleAuthenticationFailure(AbstractAuthenticationFailureEvent event) {
    log.warn("Authentication failed for user {}: {}", 
        event.getAuthentication().getName(), event.getException().getMessage());
}
```

---

## Best Practices Checklist

### ✅ Security Implementation
- [ ] Use HTTPS everywhere
- [ ] Implement proper authentication
- [ ] Apply principle of least privilege
- [ ] Validate all inputs
- [ ] Use parameterized queries
- [ ] Implement rate limiting
- [ ] Log security events
- [ ] Handle errors securely
- [ ] Keep dependencies updated
- [ ] Use security headers

### ✅ JWT Best Practices
- [ ] Use strong secret keys (256+ bits)
- [ ] Set appropriate expiration times
- [ ] Implement refresh token rotation
- [ ] Store tokens securely on client
- [ ] Validate tokens on every request
- [ ] Use HTTPS for token transmission

### ✅ Rate Limiting Best Practices
- [ ] Choose appropriate limits
- [ ] Implement different limits for different endpoints
- [ ] Provide clear error messages
- [ ] Use distributed rate limiting for microservices
- [ ] Monitor rate limit metrics
- [ ] Implement graceful degradation

---

## Common Pitfalls to Avoid

### ❌ Security Anti-patterns
- Storing passwords in plain text
- Using weak JWT secrets
- Not validating JWT expiration
- Exposing sensitive data in logs
- Not implementing rate limiting
- Using default configurations
- Not handling security exceptions properly
- Mixing authentication methods incorrectly

### ✅ Security Best Practices
- Always use HTTPS in production
- Implement defense in depth
- Follow OWASP guidelines
- Regular security audits
- Keep frameworks updated
- Use security scanning tools
- Implement proper logging and monitoring

This comprehensive guide covers all major Spring Boot Security concepts with practical examples and real-world scenarios you'll encounter in interviews.