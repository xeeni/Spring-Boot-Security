# Postman Testing Guide - Spring Boot Security

## Prerequisites
- Application running on `http://localhost:8081`
- Postman installed
- Basic understanding of HTTP headers
- Spring Boot 2.7.18 with Spring Security 5.7.x

---

## 1. Basic Authentication Testing

### **Setup Basic Auth in Postman:**

**Method 1: Authorization Tab**
1. Open new request in Postman
2. Go to **Authorization** tab
3. Select **Basic Auth** from dropdown
4. Enter credentials:
   - Username: `admin`
   - Password: `admin`

**Method 2: Manual Header**
1. Go to **Headers** tab
2. Add header:
   - Key: `Authorization`
   - Value: `Basic YWRtaW46YWRtaW4=` (base64 of admin:admin)

### **Test Cases:**

#### ✅ **Valid Admin Access**
```
GET http://localhost:8081/api/basic/admin
Authorization: Basic Auth
Username: admin
Password: admin

Expected Response: 200 OK
{
  "message": "Basic Auth - Admin endpoint",
  "user": "admin"
}
```

#### ✅ **Valid User Access**
```
GET http://localhost:8081/api/basic/user
Authorization: Basic Auth
Username: user
Password: password

Expected Response: 200 OK
{
  "message": "Basic Auth - User endpoint",
  "user": "user",
  "authorities": ["ROLE_USER"]
}
```

#### ❌ **Invalid Credentials**
```
GET http://localhost:8081/api/basic/user
Authorization: Basic Auth
Username: user
Password: wrongpassword

Expected Response: 401 Unauthorized
```

#### ❌ **Insufficient Role**
```
GET http://localhost:8081/api/basic/admin
Authorization: Basic Auth
Username: user
Password: password

Expected Response: 403 Forbidden
```

---

## 2. JWT Authentication Testing

### **Step 1: Get JWT Token**

#### **Login Request:**
```
POST http://localhost:8081/api/auth/login
Content-Type: application/json

Body (raw JSON):
{
  "username": "admin",
  "password": "admin"
}

Expected Response: 200 OK
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "role": "ADMIN"
}
```

**Copy the token from response for next requests**

### **Step 2: Use JWT Token**

#### **Setup JWT in Postman:**
1. Go to **Authorization** tab
2. Select **Bearer Token**
3. Paste the JWT token

**OR manually add header:**
- Key: `Authorization`
- Value: `Bearer eyJhbGciOiJIUzI1NiJ9...`

### **Test Cases:**

#### ✅ **JWT User Profile**
```
GET http://localhost:8081/api/jwt/user/profile
Authorization: Bearer Token
Token: <your-jwt-token>

Expected Response: 200 OK
{
  "message": "JWT - User profile",
  "user": "admin",
  "authorities": ["ROLE_ADMIN"]
}
```

#### ✅ **JWT Admin Dashboard**
```
GET http://localhost:8081/api/jwt/admin/dashboard
Authorization: Bearer Token
Token: <your-jwt-token>

Expected Response: 200 OK
{
  "message": "JWT - Admin dashboard",
  "user": "admin"
}
```

#### ❌ **Invalid JWT Token**
```
GET http://localhost:8081/api/jwt/user/profile
Authorization: Bearer Token
Token: invalid-token-here

Expected Response: 403 Forbidden
```

#### ❌ **Malformed JWT Token**
```
GET http://localhost:8081/api/jwt/user/profile
Authorization: Bearer Token
Token: eyJhbGciOiJIUzI1NiJ9.malformed.signature

Expected Response: 403 Forbidden
```

#### ❌ **Expired JWT Token (Sample)**
```
GET http://localhost:8081/api/jwt/user/profile
Authorization: Bearer Token
Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiIsImlhdCI6MTYwOTQ1OTIwMCwiZXhwIjoxNjA5NDU5MjYwfQ.invalid_signature_for_expired_token

Expected Response: 403 Forbidden
```

#### ❌ **Wrong Signature JWT Token**
```
GET http://localhost:8081/api/jwt/user/profile
Authorization: Bearer Token
Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJBRE1JTiIsImlhdCI6MTcwNjc4NDAwMCwiZXhwIjoxNzA2ODcwNDAwfQ.wrong_signature_here_for_testing

Expected Response: 403 Forbidden
```

---

## 3. API Key Authentication Testing

### **Setup API Key in Postman:**
1. Go to **Headers** tab
2. Add header:
   - Key: `X-API-Key`
   - Value: `admin-key-123` or `user-key-456`

### **Test Cases:**

#### ✅ **Admin API Key**
```
GET http://localhost:8081/api/key/data
Headers:
X-API-Key: admin-key-123

Expected Response: 200 OK
{
  "message": "API Key - Protected data",
  "user": "api-admin",
  "authorities": ["ROLE_ADMIN"]
}
```

#### ✅ **User API Key**
```
GET http://localhost:8081/api/key/data
Headers:
X-API-Key: user-key-456

Expected Response: 200 OK
{
  "message": "API Key - Protected data",
  "user": "api-user",
  "authorities": ["ROLE_USER"]
}
```

#### ❌ **Invalid API Key**
```
GET http://localhost:8081/api/key/data
Headers:
X-API-Key: wrong-key-123

Expected Response: 401 Unauthorized
Reason: Wrong API key → No authentication set
```

#### ❌ **Missing API Key**
```
GET http://localhost:8081/api/key/data
(No X-API-Key header)

Expected Response: 401 Unauthorized
Reason: No API key → No authentication set
```

---

## 4. Role-Based Access Control Testing

### **Test Cases:**

#### ✅ **User Role Access**
```
GET http://localhost:8081/api/role/user/info
Authorization: Basic Auth
Username: user
Password: password

Expected Response: 200 OK
{
  "message": "Role-based - User info",
  "user": "user"
}
```

#### ✅ **Admin Role Access**
```
GET http://localhost:8081/api/role/admin/settings
Authorization: Basic Auth
Username: admin
Password: admin

Expected Response: 200 OK
{
  "message": "Role-based - Admin settings",
  "user": "admin"
}
```

#### ❌ **User Accessing Admin Endpoint**
```
GET http://localhost:8081/api/role/admin/settings
Authorization: Basic Auth
Username: user
Password: password

Expected Response: 403 Forbidden
```

---

## 5. Method-Level Security Testing

### **Test Cases:**

#### ✅ **Admin with Correct Username**
```
GET http://localhost:8081/api/method/sensitive
Authorization: Basic Auth
Username: admin
Password: admin

Expected Response: 200 OK
{
  "message": "Method-level security - Sensitive data",
  "user": "admin"
}
```

#### ❌ **Admin with Wrong Username**
```
GET http://localhost:8081/api/method/sensitive
Authorization: Basic Auth
Username: jane  (ADMIN role but wrong username)
Password: jane123

Expected Response: 403 Forbidden
```

#### ❌ **User Role**
```
GET http://localhost:8081/api/method/sensitive
Authorization: Basic Auth
Username: user
Password: password

Expected Response: 403 Forbidden
```

---

## 6. OAuth2 Authentication Testing

### **Important Note:**
OAuth2 testing in Postman requires browser-based authentication flow. API testing is limited to endpoints that accept session cookies after web login.

### **Step 1: Web-based OAuth2 Login**
1. Open browser and go to: `http://localhost:8081/login`
2. Click "GitHub" or "Google" button
3. Complete OAuth2 authentication flow
4. You'll be redirected to dashboard with session established

### **Step 2: Extract Session Cookie**
1. In browser, open Developer Tools (F12)
2. Go to Application/Storage → Cookies
3. Copy `JSESSIONID` value

### **Step 3: Test OAuth2 Endpoints in Postman**

#### ✅ **OAuth2 User Profile**
```
GET http://localhost:8081/api/oauth2/user
Headers:
Cookie: JSESSIONID=your-session-id-here

Expected Response: 200 OK
{
  "message": "OAuth2 - User profile",
  "name": "John Doe",
  "email": "john@example.com",
  "provider": "github",
  "attributes": {...}
}
```

#### ✅ **OAuth2 Detailed Profile**
```
GET http://localhost:8081/api/oauth2/profile
Headers:
Cookie: JSESSIONID=your-session-id-here

Expected Response: 200 OK
{
  "message": "OAuth2 - User profile",
  "id": 12345,
  "name": "John Doe",
  "email": "john@example.com",
  "avatar": "https://avatars.githubusercontent.com/u/12345",
  "provider": "github"
}
```

#### ❌ **No Session Cookie**
```
GET http://localhost:8081/api/oauth2/user
(No Cookie header)

Expected Response: 401 Unauthorized
{
  "error": "Not authenticated"
}
```

#### ❌ **Invalid Session**
```
GET http://localhost:8081/api/oauth2/user
Headers:
Cookie: JSESSIONID=invalid-session-id

Expected Response: 401 Unauthorized
```

### **Alternative: Browser-based Testing**
For easier OAuth2 testing, use browser directly:
1. Login via OAuth2 at: `http://localhost:8081/login`
2. Test endpoints directly in browser:
   - `http://localhost:8081/api/oauth2/user`
   - `http://localhost:8081/api/oauth2/profile`

---

## 7. Public Endpoint Testing

### **Test Cases:**

#### ✅ **No Authentication Required**
```
GET http://localhost:8081/api/public/info
(No authorization headers needed)

Expected Response: 200 OK
{
  "message": "Public endpoint - No authentication required"
}
```

---

## 8. User Registration Testing

### **Test Cases:**

#### ✅ **Valid Registration**
```
POST http://localhost:8081/api/auth/register
Content-Type: application/json

Body (raw JSON):
{
  "username": "testuser",
  "password": "testpass123",
  "email": "test@example.com",
  "role": "USER"
}

Expected Response: 200 OK
{
  "message": "User registered successfully"
}
```

#### ❌ **Duplicate Username**
```
POST http://localhost:8081/api/auth/register
Content-Type: application/json

Body (raw JSON):
{
  "username": "admin",  (already exists)
  "password": "newpass",
  "email": "new@example.com",
  "role": "USER"
}

Expected Response: 400 Bad Request
{
  "error": "Username already exists"
}
```

---

## 9. Rate Limiting Testing

### **Test Cases:**

#### ✅ **Public Rate Limited Endpoint**
```
GET http://localhost:8081/api/rate-limit/public
(No authentication required)

Expected Response: 200 OK (first 10 requests)
{
  "message": "Public rate limiting test endpoint",
  "timestamp": 1706784000000
}

Expected Response: 429 Too Many Requests (after 10 requests)
{
  "error": "Rate limit exceeded. Max 10 requests per minute."
}
```

#### ✅ **Authenticated Rate Limited Endpoint**
```
GET http://localhost:8081/api/rate-limit/secure
Authorization: Basic Auth
Username: admin
Password: admin

Expected Response: 200 OK (first 10 requests)
{
  "message": "Rate limited secure endpoint",
  "user": "admin",
  "timestamp": 1706784000000
}

Expected Response: 429 Too Many Requests (after 10 requests)
{
  "error": "Rate limit exceeded. Max 10 requests per minute."
}
```

#### 🔄 **Rate Limit Reset Test**
```
1. Make 10 requests quickly → Get 429 error
2. Wait 1 minute
3. Make request again → Should work (200 OK)
```

---

## 10. Logout Testing

### **Test Cases:**

#### ✅ **API Logout**
```
POST http://localhost:8081/api/auth/logout
(No authentication required)

Expected Response: 200 OK
{
  "message": "Logged out successfully"
}
```

---

## Postman Collection Setup

### **Create Collection:**
1. Click **New** → **Collection**
2. Name: "Spring Boot Security Tests"
3. Add folders for each auth method

### **Environment Variables Setup:**

#### **Step 1: Create Environment**
1. Click **Environments** → **New Environment**
2. Name: "Spring Security API"
3. Add variables:
   - `baseUrl`: `http://localhost:8081`
   - `jwtToken`: (leave empty initially)
   - `adminKey`: `admin-key-123`
   - `userKey`: `user-key-456`
   - `sessionId`: (leave empty initially)
4. Click **Save**
5. Select environment from dropdown (top right)

#### **Step 2: Auto-Save JWT Token from Login**
Add this script to your **Login request**:

**In Login Request → Tests tab:**
```javascript
// Save JWT token to environment
if (pm.response.code === 200) {
    const response = pm.response.json();
    pm.environment.set("jwtToken", response.token);
    console.log("JWT Token saved:", response.token);
}
```

#### **Step 3: OAuth2 Session Cookie Script**
For OAuth2 endpoints, manually set session ID:

**In OAuth2 Request → Pre-request Script:**
```javascript
// Set session cookie for OAuth2 requests
const sessionId = pm.environment.get("sessionId");
if (sessionId) {
    pm.request.headers.add({
        key: "Cookie",
        value: `JSESSIONID=${sessionId}`
    });
}
```

## Complete Authentication Methods Summary

| Method | Header/Auth Type | Example Value |
|--------|------------------|---------------|
| **Basic Auth** | Authorization | `Basic YWRtaW46YWRtaW4=` |
| **JWT** | Authorization | `Bearer eyJhbGciOiJIUzI1NiJ9...` |
| **API Key** | X-API-Key | `admin-key-123` |
| **OAuth2** | Cookie | `JSESSIONID=session-id-here` |

## Testing Workflow

1. **Start with Public Endpoints** - No auth required
2. **Test User Registration** - Create test users
3. **Test Basic Authentication** - Username/password
4. **Get JWT Token** - Login to get token
5. **Test JWT Endpoints** - Use Bearer token
6. **Test API Key Endpoints** - Use X-API-Key header
7. **Test OAuth2** - Browser login + session cookie
8. **Test Rate Limiting** - Multiple rapid requests
9. **Test Error Scenarios** - Invalid credentials, expired tokens

This comprehensive guide covers all 7 authentication methods implemented in your Spring Boot Security project.