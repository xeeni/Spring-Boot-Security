# 🔐 Spring Boot Security Demo

A comprehensive Spring Boot application demonstrating **all major API security methods** with practical examples, rate limiting, OAuth2, and a complete web interface.

## 🚀 Features

### Security Methods Implemented
- **JWT Authentication** - Stateless token-based auth with Bearer tokens
- **Basic Authentication** - Username/password with BCrypt encryption  
- **API Key Authentication** - Header-based service-to-service auth
- **OAuth2 Authentication** - GitHub/Google social login
- **Role-Based Access Control (RBAC)** - USER and ADMIN roles
- **Method-Level Security** - Complex authorization with SpEL expressions
- **Rate Limiting** - IP-based request throttling (5 req/2min)

### Additional Features
- **Web UI** - Bootstrap interface for testing all endpoints
- **H2 Database** - In-memory database with pre-loaded users
- **Comprehensive Documentation** - API testing guides and examples
- **Request-Response Cycle Analysis** - Complete flow documentation
- **Interview Preparation Guide** - 30+ Q&A covering all concepts

## 🛠️ Tech Stack
- **Spring Boot 2.7.18** - Main framework
- **Spring Security 5.7.x** - Security implementation
- **JWT (JJWT 0.11.5)** - Token handling
- **H2 Database** - In-memory storage
- **Thymeleaf** - Web templates
- **Bootstrap 5** - UI styling
- **Maven** - Dependency management

## 📋 Default Users
| Username | Password | Role  |
|----------|----------|-------|
| admin    | admin    | ADMIN |
| user     | password | USER  |
| john     | john123  | USER  |
| jane     | jane123  | ADMIN |

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

## 🧪 API Testing Examples

### 1. JWT Authentication
```bash
# Login to get token
curl -X POST http://localhost:8081/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Use token
curl -H "Authorization: Bearer <token>" \
  http://localhost:8081/api/jwt/user/profile
```

### 2. Basic Authentication
```bash
curl -u admin:admin http://localhost:8081/api/basic/admin
curl -u user:password http://localhost:8081/api/basic/user
```

### 3. API Key Authentication
```bash
curl -H "X-API-Key: admin-key-123" http://localhost:8081/api/key/data
curl -H "X-API-Key: user-key-456" http://localhost:8081/api/key/data
```

### 4. Rate Limiting Test
```bash
# Make multiple requests quickly
for i in {1..6}; do curl http://localhost:8081/api/rate-limit/public; done
```

### 5. OAuth2 Authentication Examples

```bash
# After OAuth2 login, access OAuth2 endpoints
curl -b cookies.txt http://localhost:8081/api/oauth2/user
curl -b cookies.txt http://localhost:8081/api/oauth2/profile
```

### 6. Public Endpoint (No Authentication)

```bash
curl http://localhost:8081/api/public/info
```

## 📚 Documentation

- **PostmanTestingGuide.md** - Complete Postman testing guide
- **RequestResponseCycle.md** - Detailed request flow analysis
- **InterviewPreparation.md** - 30+ comprehensive Q&A
- **OAuth2Setup.md** - OAuth2 configuration guide
- **OAuth2FlowExplanation.md** - OAuth2 flow explanation
- **OAuth2DebuggingGuide.md** - Debug OAuth2 issues

## 🎯 Perfect For
- Learning Spring Security concepts
- API security implementation reference
- Interview preparation
- Educational demonstrations
- Security testing and validation

## 📖 Key Learning Topics
- Filter chain configuration
- Custom authentication filters
- JWT token lifecycle
- OAuth2 integration
- Rate limiting algorithms
- Method-level authorization
- Security best practices
- Error handling strategies

⭐ **Star this repo** if it helps you understand Spring Boot Security!