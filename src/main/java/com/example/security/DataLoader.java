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
    public void run(String... args) throws Exception {
        // Create default users if they don't exist
        if (userRepository.findByUsername("admin").isEmpty()) {
            User admin = new User("admin", passwordEncoder.encode("admin"), "admin@example.com", User.Role.ADMIN);
            userRepository.save(admin);
        }

        if (userRepository.findByUsername("user").isEmpty()) {
            User user = new User("user", passwordEncoder.encode("password"), "user@example.com", User.Role.USER);
            userRepository.save(user);
        }

        if (userRepository.findByUsername("john").isEmpty()) {
            User john = new User("john", passwordEncoder.encode("john123"), "john@example.com", User.Role.USER);
            userRepository.save(john);
        }

        if (userRepository.findByUsername("jane").isEmpty()) {
            User jane = new User("jane", passwordEncoder.encode("jane123"), "jane@example.com", User.Role.ADMIN);
            userRepository.save(jane);
        }

        System.out.println("Default users created:");
        System.out.println("- admin/admin (ADMIN)");
        System.out.println("- user/password (USER)");
        System.out.println("- john/john123 (USER)");
        System.out.println("- jane/jane123 (ADMIN)");
    }
}