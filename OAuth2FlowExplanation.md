# OAuth2 Authentication Flow Explained

## What is OAuth2?

OAuth2 is an **authorization framework** that allows applications to obtain limited access to user accounts on an HTTP service. Instead of using the user's password, OAuth2 uses **access tokens** to prove identity.

## Key Players

1. **Resource Owner** - The user (you)
2. **Client** - Your Spring Boot app
3. **Authorization Server** - GitHub/Google
4. **Resource Server** - GitHub/Google API

---

## OAuth2 Authorization Code Flow

### Step-by-Step Process

#### **1. User Clicks "Login with GitHub"**
```
User clicks: http://localhost:8081/oauth2/authorization/github
```

#### **2. Spring Security Redirects to GitHub**
```
Redirect to: https://github.com/login/oauth/authorize?
  client_id=your-github-client-id&
  redirect_uri=http://localhost:8081/login/oauth2/code/github&
  scope=read:user,user:email&
  response_type=code&
  state=random-state-value
```

#### **3. User Authenticates with GitHub**
- User enters GitHub username/password
- GitHub shows consent screen: "Spring Boot Security Demo wants to access your profile"
- User clicks "Authorize"

#### **4. GitHub Redirects Back with Authorization Code**
```
Redirect to: http://localhost:8081/login/oauth2/code/github?
  code=authorization-code-here&
  state=same-random-state-value
```

#### **5. Spring Security Exchanges Code for Access Token**
```java
// Spring Security automatically makes this request
POST https://github.com/login/oauth/access_token
Content-Type: application/x-www-form-urlencoded

client_id=your-github-client-id&
client_secret=your-github-client-secret&
code=authorization-code-here&
redirect_uri=http://localhost:8081/login/oauth2/code/github
```

**GitHub Response:**
```json
{
  "access_token": "gho_xxxxxxxxxxxxxxxxxxxx",
  "token_type": "bearer",
  "scope": "read:user,user:email"
}
```

#### **6. Spring Security Fetches User Information**
```java
// Spring Security automatically makes this request
GET https://api.github.com/user
Authorization: Bearer gho_xxxxxxxxxxxxxxxxxxxx
```

**GitHub Response:**
```json
{
  "id": 12345,
  "login": "johndoe",
  "name": "John Doe",
  "email": "john@example.com",
  "avatar_url": "https://avatars.githubusercontent.com/u/12345"
}
```

#### **7. Spring Security Creates Authentication**
```java
// Spring Security creates OAuth2User object
OAuth2User oauth2User = new DefaultOAuth2User(
    authorities,
    userAttributes,
    "id"  // name attribute key
);

// Sets authentication in SecurityContext
Authentication auth = new OAuth2AuthenticationToken(
    oauth2User,
    authorities,
    "github"
);
SecurityContextHolder.getContext().setAuthentication(auth);
```

#### **8. User Redirected to Dashboard**
```
Redirect to: http://localhost:8081/dashboard
```

---

## Code Flow in Your Application

### **1. SecurityConfig OAuth2 Configuration**
```java
.authorizeHttpRequests(auth -> auth
    // Allow OAuth2 callback endpoints
    .requestMatchers("/login/oauth2/**", "/oauth2/**").permitAll()
    .requestMatchers("/api/oauth2/**").authenticated()
    // ... other matchers
)
.oauth2Login(oauth2 -> oauth2
    .loginPage("/login")                    // Custom login page
    .defaultSuccessUrl("/dashboard", true)  // Redirect after success
    .failureUrl("/login?error=true")        // Redirect on failure
)
```

### **2. OAuth2 Client Registration (application.properties)**
```properties
# GitHub OAuth2 Configuration
spring.security.oauth2.client.registration.github.client-id=your-github-client-id
spring.security.oauth2.client.registration.github.client-secret=your-github-client-secret
spring.security.oauth2.client.registration.github.scope=read:user,user:email

# Google OAuth2 Configuration
spring.security.oauth2.client.registration.google.client-id=your-google-client-id
spring.security.oauth2.client.registration.google.client-secret=your-google-client-secret
spring.security.oauth2.client.registration.google.scope=openid,profile,email
```

**Spring Boot Auto-Configuration:**
- Spring Boot automatically creates `ClientRegistration` objects from properties
- No need for manual `OAuth2Config` class
- Built-in provider configurations for GitHub, Google, Facebook, etc.

### **3. Handling OAuth2 User in Controller**
```java
@GetMapping("/api/oauth2/user")
public ResponseEntity<?> getOAuth2User(@AuthenticationPrincipal OAuth2User principal) {
    return ResponseEntity.ok(Map.of(
        "name", principal.getAttribute("name"),
        "email", principal.getAttribute("email"),
        "provider", getProvider(principal)
    ));
}
```

### **4. Dashboard Integration**
```java
// In WebController.dashboard()
if (auth.getPrincipal() instanceof OAuth2User) {
    OAuth2User oauth2User = (OAuth2User) auth.getPrincipal();
    model.addAttribute("oauthProvider", getProvider(oauth2User));
    model.addAttribute("email", oauth2User.getAttribute("email"));
    model.addAttribute("avatarUrl", getAvatarUrl(oauth2User));
}
```

---

## Session Management

### **Why Sessions for OAuth2?**
Unlike JWT/API keys, OAuth2 requires **sessions** because:
- Access tokens are stored server-side
- User state needs to be maintained
- CSRF protection is enabled
- Multiple requests use same authentication

### **Session Configuration**
```java
.sessionManagement(session -> 
    session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
```

---

## Request Flow Comparison

### **Traditional Login (Form-based)**
```
1. User submits form → Spring Security validates → Creates session
2. Subsequent requests use JSESSIONID cookie
```

### **OAuth2 Login**
```
1. User clicks OAuth2 button → Redirected to provider → Provider redirects back
2. Spring Security exchanges code for token → Fetches user info → Creates session
3. Subsequent requests use JSESSIONID cookie
```

---

## Security Benefits

### **1. No Password Storage**
- Your app never sees user's GitHub/Google password
- Reduces security risk

### **2. Limited Scope**
- Only requests specific permissions (read:user, email)
- User can revoke access anytime

### **3. Delegated Authentication**
- GitHub/Google handles authentication complexity
- Multi-factor authentication handled by provider

### **4. Token-based Access**
- Access tokens can expire
- Can be revoked by user or provider

---

## OAuth2 vs Other Methods

| Aspect | OAuth2 | JWT | Basic Auth |
|--------|--------|-----|------------|
| **Password** | Never shared | Validated once | Sent every request |
| **Sessions** | Required | Not needed | Not needed |
| **Scalability** | Medium | High | High |
| **User Experience** | Excellent | Good | Poor |
| **Setup Complexity** | High | Medium | Low |
| **Security** | High | High | Medium |

---

## Error Scenarios

### **1. 404 Error on OAuth2 Callback**
```
Cause: OAuth2 callback endpoints not permitted in SecurityConfig
Solution: Add .requestMatchers("/login/oauth2/**").permitAll()
```

### **2. Invalid Client ID/Secret**
```
Error: invalid_client
Description: Client authentication failed
Solution: Verify client-id and client-secret in application.properties
```

### **3. Wrong Redirect URI**
```
Error: redirect_uri_mismatch
Description: The redirect_uri MUST match the registered callback URL
Solution: Set GitHub callback URL to: http://localhost:8081/login/oauth2/code/github
```

### **4. User Denies Permission**
```
Redirect to: http://localhost:8081/login/oauth2/code/github?
  error=access_denied&
  error_description=The+user+has+denied+your+application+access
```

### **5. Scope Issues**
```
Error: insufficient_scope
Description: The request requires higher privileges than provided
Solution: Check scope configuration in application.properties
```

---

## Testing OAuth2 Flow

### **1. GitHub OAuth App Setup**
1. Go to GitHub Settings → Developer settings → OAuth Apps
2. Create new OAuth App with:
   - **Homepage URL**: `http://localhost:8081`
   - **Authorization callback URL**: `http://localhost:8081/login/oauth2/code/github`
3. Copy Client ID and Client Secret to application.properties

### **2. Manual Testing**
```bash
# 1. Start application
mvn spring-boot:run

# 2. Open browser
http://localhost:8081/login

# 3. Click "GitHub" button
# 4. Complete OAuth2 flow
# 5. Check dashboard for OAuth2 user info
```

### **3. Debug OAuth2 Issues**
```properties
# Add to application.properties for debugging
logging.level.org.springframework.security.oauth2=DEBUG
logging.level.org.springframework.web=DEBUG
```

### **2. API Testing (After OAuth2 Login)**
```bash
# Save cookies from browser login
curl -b cookies.txt http://localhost:8081/api/oauth2/user

# Response:
{
  "message": "OAuth2 - User profile",
  "name": "John Doe",
  "email": "john@example.com",
  "provider": "github"
}
```

---

## Key Takeaways

1. **OAuth2 is authorization, not authentication** - but enables authentication
2. **Three-legged process** - User, Your App, Provider
3. **Access tokens replace passwords** - more secure
4. **Sessions required** - unlike stateless JWT
5. **Provider handles complexity** - MFA, password policies, etc.
6. **User controls access** - can revoke anytime

OAuth2 provides secure, user-friendly authentication by leveraging trusted providers like GitHub and Google, eliminating the need for users to create new accounts or share passwords with your application.