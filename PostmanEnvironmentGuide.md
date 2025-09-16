# Postman Environment Variables Guide

## 🚀 **Quick Setup for JWT Token Management**

### **Step 1: Create Environment**
1. **Click Environments** (left sidebar) → **Create Environment**
2. **Name**: "Spring Security API"
3. **Add Variables**:
   ```
   Variable Name    | Initial Value           | Current Value
   baseUrl         | http://localhost:8081   | http://localhost:8081
   jwtToken        | (empty)                 | (empty)
   adminKey        | admin-key-123           | admin-key-123
   userKey         | user-key-456            | user-key-456
   ```
4. **Save** and **Select** the environment (dropdown top-right)

---

## 🔑 **Auto-Save JWT Token from Login**

### **Login Request Setup:**
```
POST {{baseUrl}}/api/auth/login
Content-Type: application/json

Body:
{
  "username": "admin",
  "password": "admin"
}
```

### **Add to Tests Tab (Login Request):**
```javascript
// Auto-save JWT token to environment
if (pm.response.code === 200) {
    var responseJson = pm.response.json();
    pm.environment.set("jwtToken", responseJson.token);
    
    // Optional: Log the token
    console.log("JWT Token saved:", responseJson.token);
    
    // Optional: Set expiration reminder
    var expirationTime = new Date();
    expirationTime.setHours(expirationTime.getHours() + 24);
    pm.environment.set("tokenExpiration", expirationTime.toISOString());
}
```

---

## 🎯 **Using Environment Variables**

### **Method 1: Authorization Tab (Recommended)**
1. **Any JWT request** → **Authorization** tab
2. **Type**: Bearer Token
3. **Token**: `{{jwtToken}}`

### **Method 2: Headers Tab**
1. **Headers** tab
2. **Add Header**:
   - **Key**: `Authorization`
   - **Value**: `Bearer {{jwtToken}}`

### **Method 3: Pre-request Script (Advanced)**
```javascript
// Check if token exists before request
if (!pm.environment.get("jwtToken")) {
    console.log("No JWT token found. Please login first.");
}
```

---

## 📋 **Complete Request Examples**

### **1. Login (Saves Token)**
```
POST {{baseUrl}}/api/auth/login
Content-Type: application/json

Body:
{
  "username": "admin", 
  "password": "admin"
}

Tests Script:
pm.environment.set("jwtToken", pm.response.json().token);
```

### **2. JWT Protected Endpoint**
```
GET {{baseUrl}}/api/jwt/user/profile
Authorization: Bearer {{jwtToken}}
```

### **3. API Key Endpoint**
```
GET {{baseUrl}}/api/key/data
Headers:
X-API-Key: {{adminKey}}
```

### **4. Public Endpoint**
```
GET {{baseUrl}}/api/public/info
(No authorization needed)
```

---

## 🔄 **Token Management Workflow**

### **Automated Workflow:**
1. **Login Request** → Auto-saves `{{jwtToken}}`
2. **All JWT Requests** → Use `{{jwtToken}}`
3. **Token Expires** → Re-run Login Request
4. **New Token** → Automatically replaces old one

### **Manual Token Management:**
1. **Copy token** from login response
2. **Go to Environment** → Edit `jwtToken` variable
3. **Paste new token** → Save

---

## 🛠️ **Advanced Environment Scripts**

### **Global Pre-request Script:**
```javascript
// Add to Collection → Pre-request Scripts
// Auto-refresh expired tokens
var tokenExpiration = pm.environment.get("tokenExpiration");
if (tokenExpiration && new Date() > new Date(tokenExpiration)) {
    console.log("Token expired. Please login again.");
    pm.environment.unset("jwtToken");
}
```

### **Global Test Script:**
```javascript
// Add to Collection → Tests
// Handle authentication errors
if (pm.response.code === 401) {
    console.log("Authentication failed. Token may be expired.");
    pm.environment.unset("jwtToken");
}
```

---

## 📊 **Environment Variable Reference**

| Variable | Purpose | Example Value |
|----------|---------|---------------|
| `{{baseUrl}}` | API base URL | `http://localhost:8081` |
| `{{jwtToken}}` | JWT authentication token | `eyJhbGciOiJIUzI1NiJ9...` |
| `{{adminKey}}` | Admin API key | `admin-key-123` |
| `{{userKey}}` | User API key | `user-key-456` |

---

## 🎯 **Quick Test Sequence**

### **1. Setup Environment** (One-time)
- Create environment with variables
- Select environment

### **2. Login & Save Token**
```
POST {{baseUrl}}/api/auth/login
Body: {"username": "admin", "password": "admin"}
Tests: pm.environment.set("jwtToken", pm.response.json().token);
```

### **3. Test JWT Endpoints**
```
GET {{baseUrl}}/api/jwt/user/profile
Authorization: Bearer {{jwtToken}}
```

### **4. Test API Key Endpoints**
```
GET {{baseUrl}}/api/key/data
Headers: X-API-Key: {{adminKey}}
```

---

## 🔍 **Troubleshooting**

### **Token Not Saving:**
- Check if login request returns 200 status
- Verify Tests script is in correct tab
- Check console for error messages

### **Token Not Working:**
- Verify environment is selected (top-right dropdown)
- Check if `{{jwtToken}}` shows actual token value
- Ensure Bearer prefix is included: `Bearer {{jwtToken}}`

### **Environment Not Found:**
- Make sure environment is created and selected
- Check variable names match exactly (case-sensitive)
- Refresh Postman if variables don't appear

This setup allows you to login once and automatically use the JWT token for all subsequent requests!