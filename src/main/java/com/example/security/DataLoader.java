package com.example.security;

import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataLoader implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public DataLoader(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        if (userRepository.count() == 0) {
            // Create default users
            userRepository.save(new User("user", passwordEncoder.encode("password"), "user@example.com", User.Role.USER));
            userRepository.save(new User("admin", passwordEncoder.encode("admin"), "admin@example.com", User.Role.ADMIN));
            userRepository.save(new User("john", passwordEncoder.encode("john123"), "john@example.com", User.Role.USER));
            userRepository.save(new User("jane", passwordEncoder.encode("jane123"), "jane@example.com", User.Role.ADMIN));
            userRepository.save(new User("demo", passwordEncoder.encode("demo"), "demo@example.com", User.Role.USER));
            
            System.out.println("\n=== Default Users Created ===");
            System.out.println("Username: user    | Password: password | Role: USER");
            System.out.println("Username: admin   | Password: admin    | Role: ADMIN");
            System.out.println("Username: john    | Password: john123  | Role: USER");
            System.out.println("Username: jane    | Password: jane123  | Role: ADMIN");
            System.out.println("Username: demo    | Password: demo     | Role: USER");
            System.out.println("\n=== H2 Console ===");
            System.out.println("URL: http://localhost:8081/h2-console");
            System.out.println("JDBC URL: jdbc:h2:mem:securitydb");
            System.out.println("Username: sa | Password: (empty)");
            System.out.println("\n=== Web UI ===");
            System.out.println("Home: http://localhost:8081/");
            System.out.println("==============================\n");
        }
    }
}