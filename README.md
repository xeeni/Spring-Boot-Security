# Spring Boot API Security Demo

A comprehensive Spring Boot application demonstrating **all major API security methods** with practical examples.

## Security Methods Covered

### 1. **Basic Authentication**
- Username/password sent with each request
- Encoded in Base64 in Authorization header
- Built into Spring Security

### 2. **JWT (JSON Web Token)**
- Stateless token-based authentication
- Custom JWT generation and validation
- Bearer token in Authorization header

### 3. **API Key Authentication**
- Simple key-based access control
- Custom header `X-API-Key`
- Suitable for service-to-service communication

### 4. **Role-Based Access Control (RBAC)**
- USER and ADMIN roles
- Method-level security with `@PreAuthorize`
- Fine-grained permission control

### 5. **Method-Level Security**
- Advanced authorization rules
- Expression-based access control
- Complex security conditions

### 6. **OAuth2 Authentication**
- GitHub OAuth2 integration
- Google OAuth2 integration
- Social login with profile information
- Automatic JWT token generation

### 7. **Rate Limiting**
- IP-based request throttling
- 10 requests per minute limit
- 429 Too Many Requests response
- Automatic reset after time window

## Running the Application

1. Navigate to project: `cd "Spring Boot Security"`
2. **Optional**: Configure OAuth2 providers in `application.properties`
3. Run: `mvn spring-boot:run`
4. **Web UI**: http://localhost:8081
5. **H2 Console**: http://localhost:8081/h2-console

## OAuth2 Setup (Optional)

To enable OAuth2 login, update `application.properties`:

```properties
# GitHub OAuth2
spring.security.oauth2.client.registration.github.client-id=your-github-client-id
spring.security.oauth2.client.registration.github.client-secret=your-github-client-secret

# Google OAuth2
spring.security.oauth2.client.registration.google.client-id=your-google-client-id
spring.security.oauth2.client.registration.google.client-secret=your-google-client-secret
```

## Default Users

| Username | Password | Role  |
|----------|----------|-------|
| user     | password | USER  |
| admin    | admin    | ADMIN |
| john     | john123  | USER  |
| jane     | jane123  | ADMIN |
| demo     | demo     | USER  |

## Web Interface Features

- **Home Page**: Overview of security methods and endpoints
- **Login/Register**: User authentication with form-based login
- **Dashboard**: JWT token display and API testing examples
- **Users Management**: View all registered users
- **H2 Console**: Direct database access and SQL queries

## API Endpoints

### Authentication Endpoints

**Register User:**
```bash
POST /api/auth/register
Content-Type: application/json

{
  "username": "newuser",
  "password": "password123",
  "email": "user@example.com",
  "role": "USER"
}
```

**Login (Get JWT Token):**
```bash
POST /api/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "admin"
}
```

### 1. Basic Authentication Examples

```bash
# User endpoint
curl -u user:password http://localhost:8081/api/basic/user

# Admin endpoint
curl -u admin:admin http://localhost:8081/api/basic/admin
```

### 2. JWT Authentication Examples

```bash
# First, get JWT token
TOKEN=$(curl -s -X POST http://localhost:8081/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}' | jq -r '.token')

# Use JWT token
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/jwt/user/profile
curl -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/jwt/admin/dashboard
```

### 3. API Key Authentication Examples

```bash
# Admin API key
curl -H "X-API-Key: admin-key-123" http://localhost:8081/api/key/data

# User API key
curl -H "X-API-Key: user-key-456" http://localhost:8081/api/key/data
```

### 4. Role-Based Access Examples

```bash
# USER role required
curl -u user:password http://localhost:8081/api/role/user/info

# ADMIN role required
curl -u admin:admin http://localhost:8081/api/role/admin/settings
```

### 5. Method-Level Security Example

```bash
# Requires ADMIN role AND username 'admin'
curl -u admin:admin http://localhost:8081/api/method/sensitive
```

### 6. Rate Limiting Examples

```bash
# Test rate limiting (public endpoint)
for i in {1..12}; do curl http://localhost:8081/api/rate-limit/public; echo; done

# Test rate limiting (authenticated endpoint)
for i in {1..12}; do curl -u admin:admin http://localhost:8081/api/rate-limit/secure; echo; done
```

### 7. OAuth2 Authentication Examples

```bash
# After OAuth2 login, access OAuth2 endpoints
curl -b cookies.txt http://localhost:8081/api/oauth2/user
curl -b cookies.txt http://localhost:8081/api/oauth2/profile
```

### 8. Public Endpoint (No Authentication)

```bash
curl http://localhost:8081/api/public/info
```

## Security Configuration Details

### Authentication Methods Priority:
1. **JWT Token** (Bearer in Authorization header)
2. **API Key** (X-API-Key header)
3. **Basic Auth** (Authorization header)

### API Keys:
- Admin: `admin-key-123`
- User: `user-key-456`

### Role Hierarchy:
- **USER**: Access to user endpoints
- **ADMIN**: Access to both user and admin endpoints

## Testing Security

### Valid Requests:
```bash
# Basic Auth - Success
curl -u admin:admin http://localhost:8081/api/basic/admin

# JWT - Success
curl -H "Authorization: Bearer <valid-token>" http://localhost:8081/api/jwt/user/profile

# API Key - Success
curl -H "X-API-Key: admin-key-123" http://localhost:8081/api/key/data
```

### Invalid Requests:
```bash
# Wrong credentials - 401 Unauthorized
curl -u user:wrong http://localhost:8081/api/basic/user

# Invalid JWT - 403 Forbidden
curl -H "Authorization: Bearer invalid-token" http://localhost:8081/api/jwt/user/profile

# Wrong API key - 403 Forbidden
curl -H "X-API-Key: wrong-key" http://localhost:8081/api/key/data

# Insufficient role - 403 Forbidden
curl -u user:password http://localhost:8081/api/basic/admin

# Rate limit exceeded - 429 Too Many Requests
# (After 10 requests in 1 minute)
curl http://localhost:8081/api/rate-limit/public
```

## Database Features

- **H2 Console**: http://localhost:8081/h2-console
- **JDBC URL**: `jdbc:h2:mem:securitydb`
- **Username**: `sa` | **Password**: (empty)
- **Sample Data**: 5 pre-loaded users with different roles
- **SQL Queries**: Direct database access for testing
- **Auto-DDL**: Tables created automatically on startup

## Additional Features

- **Web UI**: Bootstrap-styled responsive interface
- **Password Encryption**: BCrypt hashing
- **Stateless Sessions**: No server-side session storage
- **CORS Disabled**: For development (enable for production)
- **Debug Logging**: Security events logged for troubleshooting
- **Form-based Login**: Traditional web authentication
- **JWT Dashboard**: Token display and API testing examples

## Security Best Practices Implemented

1. **Password Hashing**: BCrypt with salt
2. **JWT Expiration**: 24-hour token lifetime
3. **Stateless Design**: No session dependencies
4. **Role-Based Access**: Granular permissions
5. **Input Validation**: Bean validation annotations
6. **Secure Headers**: CSRF protection disabled for APIs
7. **Method Security**: Fine-grained authorization

## When to Use Each Method

**Basic Auth**: Simple internal APIs, development
**JWT**: Modern web/mobile apps, microservices
**API Keys**: Service-to-service, third-party integrations
**Role-Based**: Multi-tenant applications
**Method Security**: Complex business rules