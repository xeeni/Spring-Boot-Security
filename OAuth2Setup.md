# OAuth2 Setup Guide

## Overview
This guide explains how to set up OAuth2 authentication with GitHub and Google providers.

## GitHub OAuth2 Setup

### 1. Create GitHub OAuth App
1. Go to GitHub Settings → Developer settings → OAuth Apps
2. Click "New OAuth App"
3. Fill in details:
   - **Application name**: Spring Boot Security Demo
   - **Homepage URL**: http://localhost:8081
   - **Authorization callback URL**: http://localhost:8081/login/oauth2/code/github
4. Click "Register application"
5. Copy **Client ID** and **Client Secret**

### 2. Update application.properties
```properties
spring.security.oauth2.client.registration.github.client-id=your-github-client-id
spring.security.oauth2.client.registration.github.client-secret=your-github-client-secret
```

## Google OAuth2 Setup

### 1. Create Google OAuth2 Credentials
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create new project or select existing one
3. Enable Google+ API
4. Go to Credentials → Create Credentials → OAuth 2.0 Client IDs
5. Configure OAuth consent screen
6. Create OAuth 2.0 Client ID:
   - **Application type**: Web application
   - **Authorized redirect URIs**: http://localhost:8081/login/oauth2/code/google
7. Copy **Client ID** and **Client Secret**

### 2. Update application.properties
```properties
spring.security.oauth2.client.registration.google.client-id=your-google-client-id
spring.security.oauth2.client.registration.google.client-secret=your-google-client-secret
```

## Testing OAuth2

### 1. Start Application
```bash
mvn spring-boot:run
```

### 2. Access Login Page
- Navigate to: http://localhost:8081/login
- Click "GitHub" or "Google" button
- Complete OAuth2 flow
- Redirected to dashboard with OAuth2 user info

### 3. Test OAuth2 API Endpoints
```bash
# After OAuth2 login (with session cookies)
curl -b cookies.txt http://localhost:8081/api/oauth2/user
curl -b cookies.txt http://localhost:8081/api/oauth2/profile
```

## OAuth2 User Attributes

### GitHub User Attributes
```json
{
  "id": 12345,
  "login": "username",
  "name": "Full Name",
  "email": "user@example.com",
  "avatar_url": "https://avatars.githubusercontent.com/u/12345"
}
```

### Google User Attributes
```json
{
  "sub": "google-user-id",
  "name": "Full Name",
  "email": "user@gmail.com",
  "picture": "https://lh3.googleusercontent.com/..."
}
```

## Security Considerations

### Production Setup
- Use environment variables for client secrets
- Enable HTTPS
- Configure proper redirect URIs
- Set up proper OAuth consent screens
- Implement proper error handling

### Environment Variables
```bash
export GITHUB_CLIENT_ID=your-github-client-id
export GITHUB_CLIENT_SECRET=your-github-client-secret
export GOOGLE_CLIENT_ID=your-google-client-id
export GOOGLE_CLIENT_SECRET=your-google-client-secret
```

```properties
spring.security.oauth2.client.registration.github.client-id=${GITHUB_CLIENT_ID}
spring.security.oauth2.client.registration.github.client-secret=${GITHUB_CLIENT_SECRET}
spring.security.oauth2.client.registration.google.client-id=${GOOGLE_CLIENT_ID}
spring.security.oauth2.client.registration.google.client-secret=${GOOGLE_CLIENT_SECRET}
```

## Troubleshooting

### Common Issues
1. **Invalid redirect URI**: Ensure callback URL matches exactly
2. **Client secret mismatch**: Verify client ID and secret
3. **Scope issues**: Check required scopes for user information
4. **CORS errors**: Ensure proper domain configuration

### Debug Logging
```properties
logging.level.org.springframework.security.oauth2=DEBUG
logging.level.org.springframework.web.client.RestTemplate=DEBUG
```

This setup enables social login with GitHub and Google while maintaining all existing authentication methods.