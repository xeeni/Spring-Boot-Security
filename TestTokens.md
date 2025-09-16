# Test JWT Tokens for Postman Testing

## Invalid JWT Tokens for Testing

### **1. Simple Invalid Token**
```
Token: invalid-token-here
Usage: Basic invalid token test
Expected: 403 Forbidden
```

### **2. Malformed JWT Structure**
```
Token: eyJhbGciOiJIUzI1NiJ9.malformed.signature
Usage: Test malformed JWT parsing
Expected: 403 Forbidden
```

### **3. Expired JWT Token (Sample)**
```
Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiIsImlhdCI6MTYwOTQ1OTIwMCwiZXhwIjoxNjA5NDU5MjYwfQ.invalid_signature_for_expired_token

Decoded Payload:
{
  "sub": "admin",
  "role": "ADMIN", 
  "iat": 1609459200,  // Jan 1, 2021
  "exp": 1609459260   // Jan 1, 2021 (expired)
}

Usage: Test expired token validation
Expected: 403 Forbidden
```

### **4. Wrong Signature JWT Token**
```
Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiIsImlhdCI6MTcwNjc4NDAwMCwiZXhwIjoxNzA2ODcwNDAwfQ.wrong_signature_here_for_testing

Decoded Payload:
{
  "sub": "admin",
  "role": "ADMIN",
  "iat": 1706784000,  // Feb 1, 2024
  "exp": 1706870400   // Feb 2, 2024 (valid time but wrong signature)
}

Usage: Test signature validation
Expected: 403 Forbidden
```

### **5. Empty/Null Token**
```
Token: (empty)
Usage: Test missing token
Expected: 403 Forbidden
```

### **6. Token Without Bearer Prefix**
```
Header: Authorization: eyJhbGciOiJIUzI1NiJ9...
(Missing "Bearer " prefix)
Usage: Test header format validation
Expected: 403 Forbidden
```

---

## How to Generate Your Own Test Tokens

### **Create Expired Token:**
1. Modify `JwtUtil.java` temporarily:
```java
// Change expiration to past date for testing
.expiration(new Date(System.currentTimeMillis() - 3600000)) // 1 hour ago
```

2. Generate token via login endpoint
3. Revert the code change
4. Use the generated token (now expired)

### **Create Token with Wrong Signature:**
1. Get a valid token from login
2. Manually change the last part (signature) of the JWT
3. Keep header and payload intact

---

## Postman Test Examples

### **Test Invalid Token:**
```
GET http://localhost:8081/api/jwt/user/profile
Headers:
Authorization: Bearer invalid-token-here

Expected Response:
Status: 403 Forbidden
Body: (Spring Security default error response)
```

### **Test Malformed Token:**
```
GET http://localhost:8081/api/jwt/user/profile
Headers:
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.malformed.signature

Expected Response:
Status: 403 Forbidden
Body: (JWT parsing error)
```

### **Test Expired Token:**
```
GET http://localhost:8081/api/jwt/user/profile
Headers:
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiIsImlhdCI6MTYwOTQ1OTIwMCwiZXhwIjoxNjA5NDU5MjYwfQ.invalid_signature_for_expired_token

Expected Response:
Status: 403 Forbidden
Body: (Token expired error)
```

---

## JWT Token Structure Explanation

### **Valid JWT Format:**
```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiIsImlhdCI6MTcwNjc4NDAwMCwiZXhwIjoxNzA2ODcwNDAwfQ.signature_here
     ^HEADER^              ^PAYLOAD^                                                                    ^SIGNATURE^
```

### **Header (Base64 decoded):**
```json
{
  "alg": "HS256"
}
```

### **Payload (Base64 decoded):**
```json
{
  "sub": "admin",
  "role": "ADMIN",
  "iat": 1706784000,
  "exp": 1706870400
}
```

### **Signature:**
- HMACSHA256(base64UrlEncode(header) + "." + base64UrlEncode(payload), secret)

---

## Testing Scenarios in Postman

### **1. Token Validation Flow:**
```
Valid Token → JwtAuthenticationFilter → JwtUtil.isTokenValid() → Success
Invalid Token → JwtAuthenticationFilter → JwtUtil.isTokenValid() → Exception → 403
```

### **2. Common Test Cases:**
- ✅ Valid token with correct signature
- ❌ Token with wrong signature
- ❌ Expired token
- ❌ Malformed token structure
- ❌ Missing Bearer prefix
- ❌ Empty/null token
- ❌ Token signed with different secret

### **3. Expected Responses:**
- **Valid Token**: 200 OK with data
- **Invalid Token**: 401 Unauthorized (no authentication set)
- **No Token**: 401 Unauthorized (falls through to other auth methods)
- **Valid Token + Wrong Role**: 403 Forbidden (authenticated but not authorized)

---

## Your Token Analysis

**Your Original Token:**
```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiIsImlhdCI6MTc1Nzg4MzQxMywiZXhwIjoxNzU3OTY5ODEzfQ.E_a4FCvmt2ByxggqSPCo94JBElEPZP1o19jR_vTXeVI

Decoded Payload:
{
  "sub": "admin",
  "role": "ADMIN",
  "iat": 1757883413,  // Jan 15, 2026 (future date - valid)
  "exp": 1757969813   // Jan 16, 2026 (future date - valid)
}
```

## Modified Test Tokens from Your Token

### **1. Expired Version (Changed exp to past date):**
```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiIsImlhdCI6MTc1Nzg4MzQxMywiZXhwIjoxNjA5NDU5MjAwfQ.E_a4FCvmt2ByxggqSPCo94JBElEPZP1o19jR_vTXeVI

Payload: Same as yours but exp changed to 1609459200 (Jan 1, 2021 - expired)
Expected: 403 Forbidden (token expired)
```

### **2. Invalid Signature Version:**
```
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiIsImlhdCI6MTc1Nzg4MzQxMywiZXhwIjoxNzU3OTY5ODEzfQ.INVALID_SIGNATURE_FOR_TESTING

Payload: Exactly same as yours but signature changed
Expected: 403 Forbidden (signature verification failed)
```

### **3. Malformed Version:**
```
eyJhbGciOiJIUzI1NiJ9.MALFORMED_PAYLOAD.E_a4FCvmt2ByxggqSPCo94JBElEPZP1o19jR_vTXeVI

Payload: Corrupted middle part
Expected: 403 Forbidden (JWT parsing error)
```

## Why You're Getting 401 Instead of 403

**The issue is in your Spring Security configuration:**

```java
// In SecurityConfig, you probably have:
.authorizeHttpRequests(auth -> auth
    .requestMatchers("/api/jwt/**").authenticated()  // This requires authentication
)
```

**When JWT fails:**
1. JwtAuthenticationFilter doesn't set authentication
2. Spring Security sees no authentication
3. Returns 401 Unauthorized (not 403 Forbidden)

**To get 403 Forbidden, the endpoint needs to be accessible but authorization fails**

## Quick Copy-Paste Test Tokens

**Based on Your Token:**
```
# Expired token
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiIsImlhdCI6MTc1Nzg4MzQxMywiZXhwIjoxNjA5NDU5MjAwfQ.E_a4FCvmt2ByxggqSPCo94JBElEPZP1o19jR_vTXeVI

# Invalid signature
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiIsImlhdCI6MTc1Nzg4MzQxMywiZXhwIjoxNzU3OTY5ODEzfQ.INVALID_SIGNATURE_FOR_TESTING

# Malformed
eyJhbGciOiJIUzI1NiJ9.MALFORMED_PAYLOAD.E_a4FCvmt2ByxggqSPCo94JBElEPZP1o19jR_vTXeVI

# Simple invalid
invalid-token-here
```

**All should return 401 Unauthorized (which is correct for your setup)**