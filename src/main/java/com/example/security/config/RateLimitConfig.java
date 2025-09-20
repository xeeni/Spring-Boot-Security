/**
 * @author Zeenat Hussain
 */
package com.example.security.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "rate-limit")
public class RateLimitConfig {
    
    private int maxRequests = 10;
    private long timeWindowMinutes = 1;
    private boolean enabled = true;
    private String[] excludedPaths = {"/api/public/info", "/h2-console/**"};
    
    // Getters and setters
    public int getMaxRequests() { return maxRequests; }
    public void setMaxRequests(int maxRequests) { this.maxRequests = maxRequests; }
    
    public long getTimeWindowMinutes() { return timeWindowMinutes; }
    public void setTimeWindowMinutes(long timeWindowMinutes) { this.timeWindowMinutes = timeWindowMinutes; }
    
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    
    public String[] getExcludedPaths() { return excludedPaths; }
    public void setExcludedPaths(String[] excludedPaths) { this.excludedPaths = excludedPaths; }
    
    public long getTimeWindowMillis() { return timeWindowMinutes * 60 * 1000; }
}