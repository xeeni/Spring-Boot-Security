/**
 * @author Zeenat Hussain
 */
package com.example.security.controller;

import com.example.security.model.User;
import com.example.security.repository.UserRepository;
import com.example.security.util.JwtUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

@Controller
public class WebController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    public WebController(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtUtil jwtUtil) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    @GetMapping("/")
    public String home(Model model, Authentication auth) {
        model.addAttribute("authenticated", auth != null);
        if (auth != null) {
            model.addAttribute("username", auth.getName());
            model.addAttribute("authorities", auth.getAuthorities());
        }
        return "index";
    }

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/register")
    public String registerPage() {
        return "register";
    }

    @PostMapping("/register")
    public String register(@RequestParam String username, @RequestParam String password, 
                          @RequestParam String email, @RequestParam String role,
                          RedirectAttributes redirectAttributes) {
        if (userRepository.findByUsername(username).isPresent()) {
            redirectAttributes.addFlashAttribute("error", "Username already exists");
            return "redirect:/register";
        }

        User user = new User(username, passwordEncoder.encode(password), email, User.Role.valueOf(role));
        userRepository.save(user);
        
        redirectAttributes.addFlashAttribute("success", "Registration successful! Please login.");
        return "redirect:/login";
    }

    @PostMapping("/web-login")
    public String webLogin(@RequestParam String username, @RequestParam String password, 
                          RedirectAttributes redirectAttributes, Model model) {
        User user = userRepository.findByUsername(username).orElse(null);
        
        if (user == null || !passwordEncoder.matches(password, user.getPassword())) {
            redirectAttributes.addFlashAttribute("error", "Invalid credentials");
            return "redirect:/login";
        }

        String token = jwtUtil.generateToken(username, user.getRole().name());
        model.addAttribute("token", token);
        model.addAttribute("username", username);
        model.addAttribute("role", user.getRole().name());
        return "dashboard";
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model, Authentication auth) {
        if (auth == null) {
            return "redirect:/login";
        }
        
        model.addAttribute("username", auth.getName());
        model.addAttribute("authorities", auth.getAuthorities());
        
        // Check if OAuth2 authentication
        if (auth.getPrincipal() instanceof OAuth2User) {
            OAuth2User oauth2User = (OAuth2User) auth.getPrincipal();
            model.addAttribute("oauthProvider", getProvider(oauth2User));
            model.addAttribute("email", oauth2User.getAttribute("email"));
            model.addAttribute("avatarUrl", getAvatarUrl(oauth2User));
            
            // Generate JWT token for OAuth2 user
            String token = jwtUtil.generateToken(auth.getName(), "USER");
            model.addAttribute("token", token);
            model.addAttribute("role", "USER");
        } else {
            // Regular user - try to get role from database
            User user = userRepository.findByUsername(auth.getName()).orElse(null);
            if (user != null) {
                String token = jwtUtil.generateToken(auth.getName(), user.getRole().name());
                model.addAttribute("token", token);
                model.addAttribute("role", user.getRole().name());
            }
        }
        
        return "dashboard";
    }

    @GetMapping("/users")
    public String users(Model model, Authentication auth) {
        if (auth == null) {
            return "redirect:/login";
        }
        model.addAttribute("users", userRepository.findAll());
        return "users";
    }

    @PostMapping("/logout")
    public String logout() {
        return "redirect:/login?logout";
    }
    
    private String getProvider(OAuth2User principal) {
        if (principal.getAttribute("login") != null) {
            return "GitHub";
        } else if (principal.getAttribute("sub") != null) {
            return "Google";
        }
        return "Unknown";
    }

    private String getAvatarUrl(OAuth2User principal) {
        String provider = getProvider(principal);
        if ("GitHub".equals(provider)) {
            return principal.getAttribute("avatar_url");
        } else if ("Google".equals(provider)) {
            return principal.getAttribute("picture");
        }
        return null;
    }
}