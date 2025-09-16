# Complete Request-Response Cycle Guide

## Filter Chain Order
```
Request → RateLimitingFilter → JwtAuthenticationFilter → UsernamePasswordAuthenticationFilter → OAuth2LoginAuthenticationFilter → Controller
```

**Note**: OAuth2 uses Spring Security's built-in filters (auto-configured):
- **OAuth2 Login**: OAuth2AuthorizationRequestRedirectFilter → OAuth2LoginAuthenticationFilter
- **OAuth2 API Requests**: Standard session-based authentication
- **Your Custom Filters**: RateLimitingFilter → JwtAuthenticationFilter (for JWT/API keys)

---

## 1. Public Endpoints (No Authentication)

### `GET /api/public/info`
```
1. Request arrives
2. RateLimitingFilter: Checks excluded paths → SKIP (excluded)
3. SecurityConfig: .permitAll() → ALLOW
4. SecureController.publicInfo() → Execute
5. Response: {"message": "Public endpoint - No authentication required"}
```

### `POST /api/auth/register`
```
1. Request with JSON body
2. RateLimitingFilter: SKIP (excluded path)
3. SecurityConfig: /api/auth/** → .permitAll()
4. AuthController.register():
   - Check username exists → userRepository.findByUsername()
   - Encrypt password → passwordEncoder.encode()
   - Save user → userRepository.save()
5. Response: {"message": "User registered successfully"}
```

### `POST /api/auth/login`
```
1. Request with credentials
2. RateLimitingFilter: SKIP
3. AuthController.login():
   - Find user → userRepository.findByUsername()
   - Verify password → passwordEncoder.matches()
   - Generate JWT → jwtUtil.generateToken()
4. Response: {"token": "eyJ...", "role": "ADMIN"}
```

---

## 2. Rate Limited Endpoints

### `GET /api/rate-limit/public`
```
1. Request arrives
2. RateLimitingFilter:
   - Get client IP → request.getRemoteAddr()
   - Check rate limit → rateLimitService.isAllowed(clientId)
   - If allowed: Add headers (X-RateLimit-*) → Continue
   - If exceeded: Return 429 + error JSON → STOP
3. SecurityConfig: .permitAll() → ALLOW
4. RateLimitController.publicRateLimitTest() → Execute
5. Response: {"message": "Public rate limiting test endpoint"}
```

### `GET /api/rate-limit/secure` (with Basic Auth)
```
1. Request with Authorization: Basic YWRtaW46YWRtaW4=
2. RateLimitingFilter: Check rate limit → Continue if allowed
3. JwtAuthenticationFilter: No Bearer token → Skip JWT
4. UsernamePasswordAuthenticationFilter:
   - Decode Base64 → "admin:admin"
   - Load user → CustomUserDetailsService.loadUserByUsername()
   - Verify password → BCrypt comparison
   - Set authentication → SecurityContextHolder
5. SecurityConfig: Requires USER/ADMIN role → ALLOW
6. SecureController.rateLimitSecure() → Execute
7. Response: {"message": "Rate limited secure endpoint", "user": "admin"}
```

---

## 3. JWT Authentication Endpoints

### `GET /api/jwt/user/profile` (with Bearer Token)
```
1. Request with Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
2. RateLimitingFilter: Check rate limit → Continue
3. JwtAuthenticationFilter:
   - Extract Bearer token → "eyJhbGciOiJIUzI1NiJ9..."
   - Validate token → jwtUtil.isTokenValid()
   - Extract claims → jwtUtil.extractUsername() + extractRole()
   - Create authentication → UsernamePasswordAuthenticationToken
   - Set in context → SecurityContextHolder.setAuthentication()
4. SecurityConfig: /api/jwt/user/** requires USER/ADMIN → ALLOW
5. SecureController.jwtUserProfile() → Execute
6. Response: {"message": "JWT - User profile", "user": "admin"}
```

### `GET /api/jwt/admin/dashboard` (Admin Only)
```
1-3. Same JWT validation as above
4. SecurityConfig: /api/jwt/admin/** requires ADMIN role → Check role
5. If ADMIN: SecureController.jwtAdminDashboard() → Execute
6. If USER: Return 403 Forbidden
```

---

## 4. API Key Authentication

### `GET /api/key/data` (with X-API-Key)
```
1. Request with X-API-Key: admin-key-123
2. RateLimitingFilter: Check rate limit → Continue
3. JwtAuthenticationFilter:
   - No Authorization header → Check X-API-Key
   - Validate key → Hardcoded check ("admin-key-123" or "user-key-456")
   - Create authentication → Set role based on key
   - admin-key-123 → ROLE_ADMIN, user "api-admin"
   - user-key-456 → ROLE_USER, user "api-user"
4. SecurityConfig: /api/key/** requires USER/ADMIN → ALLOW
5. SecureController.apiKeyData() → Execute
6. Response: {"message": "API Key - Protected data", "user": "api-admin"}
```

---

## 5. Basic Authentication Endpoints

### `GET /api/basic/user` (Any authenticated user)
```
1. Request with Authorization: Basic dXNlcjpwYXNzd29yZA==
2. RateLimitingFilter: Check rate limit → Continue
3. JwtAuthenticationFilter: No Bearer/API key → Skip
4. UsernamePasswordAuthenticationFilter:
   - Decode Base64 → "user:password"
   - Load user details → CustomUserDetailsService
   - Database query → userRepository.findByUsername("user")
   - Password verification → BCrypt.matches()
   - Set authentication with USER role
5. SecurityConfig: /api/basic/** requires USER/ADMIN → ALLOW
6. SecureController.basicUser() → Execute
7. Response: {"message": "Basic Auth - User endpoint", "user": "user"}
```

### `GET /api/basic/admin` (Admin required)
```
1-4. Same basic auth flow
5. SecurityConfig: Allows USER/ADMIN → Continue
6. Method-level: @PreAuthorize("hasRole('ADMIN')") → Check role
7. If ADMIN: SecureController.basicAdmin() → Execute
8. If USER: Return 403 Forbidden
```

---

## 6. OAuth2 Authentication Endpoints

### OAuth2 Login Flow (Browser-based)
```
1. User clicks "Login with GitHub" → /oauth2/authorization/github
2. Spring Security OAuth2AuthorizationRequestRedirectFilter:
   - Generates authorization request
   - Redirects to GitHub: https://github.com/login/oauth/authorize?
     client_id=your-client-id&
     redirect_uri=http://localhost:8081/login/oauth2/code/github&
     scope=read:user,user:email&
     state=random-state
3. User authenticates with GitHub → GitHub shows consent screen
4. GitHub redirects back: /login/oauth2/code/github?code=auth-code&state=state
5. Spring Security OAuth2LoginAuthenticationFilter:
   - Validates state parameter
   - Exchanges authorization code for access token
   - Fetches user info from GitHub API
   - Creates OAuth2User with GitHub user attributes
   - Creates OAuth2AuthenticationToken
   - Stores authentication in HTTP session
6. Redirect to dashboard → /dashboard (with JSESSIONID cookie)
```

### `GET /api/oauth2/user` (with Session Cookie)
```
1. Request with Cookie: JSESSIONID=session-id
2. RateLimitingFilter: Check rate limit → Continue
3. Spring Security Session Management:
   - Extract JSESSIONID from cookie
   - Lookup session in SessionRepository
   - Retrieve stored OAuth2AuthenticationToken
   - Set authentication in SecurityContextHolder
4. SecurityConfig: /api/oauth2/** requires authenticated() → ALLOW
5. OAuth2Controller.getOAuth2User():
   - Extract OAuth2User from Authentication
   - Get user attributes (name, email, avatar)
   - Determine provider (GitHub/Google)
6. Response: {
     "message": "OAuth2 - User profile",
     "name": "John Doe",
     "email": "john@example.com",
     "provider": "github"
   }
```

### `GET /api/oauth2/profile` (Detailed Profile)
```
1-4. Same OAuth2 session authentication as above
5. OAuth2Controller.getProfile():
   - Extract detailed user attributes
   - Get avatar URL based on provider
   - Format provider-specific data
6. Response: {
     "message": "OAuth2 - User profile",
     "id": 12345,
     "name": "John Doe",
     "email": "john@example.com",
     "avatar": "https://avatars.githubusercontent.com/u/12345",
     "provider": "github"
   }
```

### OAuth2 vs Other Authentication Methods
```
OAuth2 Flow:
Browser → GitHub → Callback → Session Created → API Requests use Session

JWT Flow:
Login API → JWT Token → API Requests use Bearer Token

Basic Auth Flow:
API Requests → Username/Password in each request
```

---

## 7. Role-Based Access Control

### `GET /api/role/user/info` (USER role only)
```
1-4. Authentication (any method: Basic/JWT/API Key)
5. SecurityConfig: /api/role/user/** → Continue
6. Method-level: @PreAuthorize("hasRole('USER')") → Check exact role
7. If USER: SecureController.userInfo() → Execute
8. If ADMIN: Return 403 Forbidden (ADMIN ≠ USER)
```

### `GET /api/role/admin/settings` (ADMIN role only)
```
1-4. Authentication flow
5-6. @PreAuthorize("hasRole('ADMIN')") → Check role
7. If ADMIN: SecureController.adminSettings() → Execute
8. If USER: Return 403 Forbidden
```

---

## 7. Method-Level Security (Complex Rules)

### `GET /api/method/sensitive` (ADMIN + username = "admin")
```
1-4. Authentication (typically Basic Auth)
5. Method-level: @PreAuthorize("hasRole('ADMIN') and authentication.name == 'admin'")
6. Expression evaluation:
   - hasRole('ADMIN') → Check if user has ADMIN role
   - authentication.name == 'admin' → Check exact username
   - Both must be true
7. If admin/admin: SecureController.sensitiveData() → Execute
8. If jane/ADMIN: Return 403 (wrong username)
9. If user/USER: Return 403 (wrong role)
```

---

## 9. Rate Limiting Scenarios

### First 10 Requests (Within Limit)
```
Client IP: 192.168.1.100
Time: 10:00:00-10:00:50

1. RateLimitingFilter:
   - rateLimitService.isAllowed("192.168.1.100") → true
   - Add headers: X-RateLimit-Remaining: 9,8,7...1,0
2. Continue to authentication
3. Normal response with rate limit headers
```

### 11th Request (Rate Limited)
```
Time: 10:00:55

1. RateLimitingFilter:
   - rateLimitService.isAllowed("192.168.1.100") → false
   - Set status: 429 Too Many Requests
   - Add headers: Retry-After: 65, X-RateLimit-Remaining: 0
   - Return error JSON → STOP (no further processing)
```

### After Window Reset
```
Time: 10:01:05 (65 seconds later)

1. RateLimitingFilter:
   - Window expired → Create new window
   - rateLimitService.isAllowed() → true (count reset to 1)
2. Continue normal processing
```

---

## Error Scenarios

### Invalid JWT Token
```
1. Request with Authorization: Bearer invalid-token
2. JwtAuthenticationFilter:
   - jwtUtil.isTokenValid("invalid-token") → false
   - No authentication set
3. SecurityConfig: Protected endpoint requires auth → 401 Unauthorized
```

### Wrong API Key
```
1. Request with X-API-Key: wrong-key
2. JwtAuthenticationFilter:
   - Key doesn't match hardcoded values → No authentication
3. SecurityConfig: Protected endpoint → 401 Unauthorized
```

### Insufficient Role
```
1. USER tries to access ADMIN endpoint
2. Authentication successful (USER role set)
3. @PreAuthorize("hasRole('ADMIN')") → false
4. Return 403 Forbidden
```

---

## Key Components Summary

**Filters (in order):**
1. `RateLimitingFilter` - Request throttling
2. `JwtAuthenticationFilter` - JWT/API key validation
3. `UsernamePasswordAuthenticationFilter` - Basic auth

**Security Layers:**
1. **URL-based**: SecurityConfig.authorizeHttpRequests()
2. **Method-based**: @PreAuthorize annotations
3. **Rate limiting**: IP-based request counting

**Authentication Methods:**
1. **JWT**: Bearer token in Authorization header
2. **API Key**: X-API-Key header with predefined keys
3. **Basic Auth**: Base64 encoded username:password
4. **OAuth2**: Session-based with JSESSIONID cookie

**Data Flow:**
- `UserRepository` → JPA queries → H2 Database
- `PasswordEncoder` → BCrypt hashing/verification
- `JwtUtil` → Token generation/validation