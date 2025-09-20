# OAuth2 Debugging Guide - Breakpoints & Internal Flow

## IDE Debugging Setup

### **1. Enable Debug Logging**
Add to `application.properties`:
```properties
logging.level.org.springframework.security.oauth2=TRACE
logging.level.org.springframework.security.web=DEBUG
logging.level.org.springframework.web.client.RestTemplate=DEBUG
logging.level.org.springframework.http=DEBUG
```

---

## OAuth2 Authorization Flow Breakpoints

### **Step 1: Authorization Request (GitHub Redirect)**

#### **Breakpoint Locations:**
```java
// Spring Security Internal Classes (Add to IDE breakpoints)
org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.doFilterInternal()
org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver.resolve()
```

#### **What to Debug:**
- Authorization URL generation
- Client ID and redirect URI
- State parameter generation
- Scope configuration

#### **Debug Variables:**
```java
// In OAuth2AuthorizationRequestRedirectFilter
OAuth2AuthorizationRequest authorizationRequest
String authorizationRequestUri
ClientRegistration clientRegistration
```

---

### **Step 2: Authorization Code Callback**

#### **Breakpoint Locations:**
```java
// Spring Security Internal Classes
org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter.attemptAuthentication()
org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationProvider.authenticate()
```

#### **What to Debug:**
- Authorization code extraction
- State parameter validation
- Token exchange preparation

#### **Debug Variables:**
```java
// In OAuth2LoginAuthenticationFilter
String code = request.getParameter("code")
String state = request.getParameter("state")
OAuth2AuthorizationRequest authorizationRequest
```

---

### **Step 3: Token Exchange (Code for Access Token)**

#### **Breakpoint Locations:**
```java
// Spring Security Internal Classes
org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient.getTokenResponse()
org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler.handleError()
```

#### **What to Debug:**
- HTTP request to GitHub token endpoint
- Client authentication (client_id, client_secret)
- Token response parsing

#### **Debug Variables:**
```java
// In DefaultAuthorizationCodeTokenResponseClient
OAuth2AuthorizationCodeGrantRequest tokenRequest
RequestEntity<?> request  // HTTP request to GitHub
ResponseEntity<OAuth2AccessTokenResponse> response
```

#### **Network Request Details:**
```java
// Debug the actual HTTP request
POST https://github.com/login/oauth/access_token
Headers: {
  "Accept": "application/json",
  "Content-Type": "application/x-www-form-urlencoded"
}
Body: {
  "grant_type": "authorization_code",
  "code": "authorization_code_here",
  "redirect_uri": "http://localhost:8081/login/oauth2/code/github",
  "client_id": "your_client_id",
  "client_secret": "your_client_secret"
}
```

---

### **Step 4: User Info Retrieval**

#### **Breakpoint Locations:**
```java
// Spring Security Internal Classes
org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService.loadUser()
org.springframework.security.oauth2.client.userinfo.OAuth2UserRequestEntityConverter.convert()
```

#### **What to Debug:**
- Access token usage
- User info API call to GitHub
- User attributes mapping

#### **Debug Variables:**
```java
// In DefaultOAuth2UserService
OAuth2UserRequest userRequest
OAuth2AccessToken accessToken
RequestEntity<?> request  // HTTP request to GitHub user API
Map<String, Object> userAttributes
```

#### **Network Request Details:**
```java
// Debug the user info request
GET https://api.github.com/user
Headers: {
  "Authorization": "Bearer gho_xxxxxxxxxxxxxxxxxxxx",
  "Accept": "application/json"
}
```

---

### **Step 5: OAuth2User Creation**

#### **Breakpoint Locations:**
```java
// Spring Security Internal Classes
org.springframework.security.oauth2.core.user.DefaultOAuth2User.<init>()
org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationProvider.authenticate()
```

#### **What to Debug:**
- User attributes processing
- Authorities assignment
- OAuth2User object creation

#### **Debug Variables:**
```java
// In DefaultOAuth2User constructor
Collection<? extends GrantedAuthority> authorities
Map<String, Object> attributes
String nameAttributeKey  // "id" for GitHub
```

---

### **Step 6: Authentication Token Creation**

#### **Breakpoint Locations:**
```java
// Spring Security Internal Classes
org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken.<init>()
org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter.successfulAuthentication()
```

#### **What to Debug:**
- OAuth2AuthenticationToken creation
- Session storage
- Success handler execution

#### **Debug Variables:**
```java
// In OAuth2LoginAuthenticationToken
OAuth2User principal
Collection<? extends GrantedAuthority> authorities
String authorizedClientRegistrationId  // "github"
```

---

## Your Application Breakpoints

### **Dashboard Controller**
```java
// In WebController.dashboard()
@GetMapping("/dashboard")
public String dashboard(Model model, Authentication auth) {
    // BREAKPOINT HERE
    if (auth.getPrincipal() instanceof OAuth2User) {
        OAuth2User oauth2User = (OAuth2User) auth.getPrincipal();
        // Debug oauth2User attributes
        Map<String, Object> attributes = oauth2User.getAttributes();
        String name = oauth2User.getAttribute("name");
        String email = oauth2User.getAttribute("email");
    }
}
```

### **OAuth2 API Controller**
```java
// In OAuth2Controller.getOAuth2User()
@GetMapping("/api/oauth2/user")
public ResponseEntity<?> getOAuth2User(@AuthenticationPrincipal OAuth2User principal) {
    // BREAKPOINT HERE
    if (principal == null) {
        return ResponseEntity.status(401).body(Map.of("error", "Not authenticated"));
    }
    
    // Debug principal attributes
    Map<String, Object> attributes = principal.getAttributes();
    String provider = getProvider(principal);
}
```

---

## Debug Session Flow

### **1. Start Debug Session**
1. Set breakpoints in Spring Security classes (add to IDE)
2. Start application in debug mode
3. Open browser: `http://localhost:8081/login`
4. Click "GitHub" button

### **2. Authorization Request Debug**
```
Breakpoint: OAuth2AuthorizationRequestRedirectFilter.doFilterInternal()
Variables to inspect:
- authorizationRequest.getAuthorizationUri()
- authorizationRequest.getClientId()
- authorizationRequest.getRedirectUri()
- authorizationRequest.getState()
```

### **3. Callback Processing Debug**
```
Breakpoint: OAuth2LoginAuthenticationFilter.attemptAuthentication()
Variables to inspect:
- request.getParameter("code")
- request.getParameter("state")
- authorizationRequest (from session)
```

### **4. Token Exchange Debug**
```
Breakpoint: DefaultAuthorizationCodeTokenResponseClient.getTokenResponse()
Variables to inspect:
- tokenRequest.getAuthorizationExchange()
- HTTP request entity
- HTTP response entity
- accessToken.getTokenValue()
```

### **5. User Info Debug**
```
Breakpoint: DefaultOAuth2UserService.loadUser()
Variables to inspect:
- userRequest.getAccessToken()
- HTTP request to user info endpoint
- userAttributes map
- nameAttributeKey
```

### **6. Your Controller Debug**
```
Breakpoint: WebController.dashboard()
Variables to inspect:
- auth.getPrincipal() (OAuth2User)
- oauth2User.getAttributes()
- Session ID
```

---

## Network Traffic Monitoring

### **Using Browser DevTools:**
1. Open DevTools (F12)
2. Go to Network tab
3. Start OAuth2 flow
4. Monitor requests:
   - Redirect to GitHub
   - GitHub callback
   - Dashboard redirect

### **Using Proxy Tools:**
- **Burp Suite** or **OWASP ZAP** for detailed HTTP analysis
- **Wireshark** for network packet analysis

---

## Common Debug Scenarios

### **Token Exchange Failure**
```java
// Breakpoint in OAuth2ErrorResponseErrorHandler
public void handleError(ClientHttpResponse response) {
    // Debug HTTP error response
    String responseBody = // read response body
    HttpStatus statusCode = response.getStatusCode();
}
```

### **User Info Retrieval Failure**
```java
// Breakpoint in DefaultOAuth2UserService
try {
    ResponseEntity<Map<String, Object>> response = restOperations.exchange(request, PARAMETERIZED_RESPONSE_TYPE);
} catch (OAuth2AuthorizationException ex) {
    // Debug OAuth2 exception
    OAuth2Error error = ex.getError();
}
```

### **Session Issues**
```java
// Debug session storage
HttpSession session = request.getSession();
SecurityContext securityContext = (SecurityContext) session.getAttribute("SPRING_SECURITY_CONTEXT");
Authentication authentication = securityContext.getAuthentication();
```

---

## Debugging Tips

### **1. Enable All OAuth2 Logging**
```properties
logging.level.org.springframework.security.oauth2=TRACE
logging.level.org.springframework.web.client=DEBUG
logging.level.org.springframework.http.client=DEBUG
```

### **2. Use Conditional Breakpoints**
```java
// Only break when specific conditions are met
auth.getPrincipal() instanceof OAuth2User
```

### **3. Watch Expressions**
```java
// Add to IDE watch window
((OAuth2User) auth.getPrincipal()).getAttributes()
request.getSession().getId()
SecurityContextHolder.getContext().getAuthentication()
```

### **4. Log Custom Information**
```java
// Add temporary logging
log.debug("OAuth2 User: {}", oauth2User.getAttributes());
log.debug("Session ID: {}", request.getSession().getId());
log.debug("Access Token: {}", accessToken.getTokenValue());
```

This debugging guide will help you trace the complete OAuth2 flow from authorization request to user session creation, allowing you to see exactly how Spring Security handles the token exchange and user info retrieval internally.