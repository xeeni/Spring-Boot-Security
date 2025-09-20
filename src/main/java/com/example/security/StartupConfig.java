package com.example.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class StartupConfig {

    @Value("${server.port:8080}")
    private String serverPort;

    @Value("${spring.h2.console.path:/h2-console}")
    private String h2ConsolePath;

    @EventListener(ApplicationReadyEvent.class)
    public void onApplicationReady() {
        System.out.println("\n" + "=".repeat(80));
        System.out.println("🚀 SPRING BOOT SECURITY DEMO - APPLICATION STARTED SUCCESSFULLY!");
        System.out.println("=".repeat(80));
        System.out.println("📍 Server URL:        http://localhost:" + serverPort);
        System.out.println("🌐 Web Interface:     http://localhost:" + serverPort + "/");
        System.out.println("🔑 Login Page:        http://localhost:" + serverPort + "/login");
        System.out.println("🗄️  H2 Database:      http://localhost:" + serverPort + h2ConsolePath);
        System.out.println("📚 API Documentation: Check README.md and PostmanTestingGuide.md");
        System.out.println("=".repeat(80));
        System.out.println("👥 Default Users:");
        System.out.println("   • admin/admin (ADMIN role)");
        System.out.println("   • user/password (USER role)");
        System.out.println("   • john/john123 (USER role)");
        System.out.println("   • jane/jane123 (ADMIN role)");
        System.out.println("=".repeat(80));
        System.out.println("🔐 Authentication Methods Available:");
        System.out.println("   ✅ JWT Authentication");
        System.out.println("   ✅ Basic Authentication");
        System.out.println("   ✅ API Key Authentication");
        System.out.println("   ✅ OAuth2 Authentication (GitHub/Google)");
        System.out.println("   ✅ Role-Based Access Control");
        System.out.println("   ✅ Method-Level Security");
        System.out.println("   ✅ Rate Limiting");
        System.out.println("=".repeat(80));
        System.out.println("🧪 Quick API Tests:");
        System.out.println("   curl http://localhost:" + serverPort + "/api/public/info");
        System.out.println("   curl -u admin:admin http://localhost:" + serverPort + "/api/basic/user");
        System.out.println("=".repeat(80) + "\n");
    }
}