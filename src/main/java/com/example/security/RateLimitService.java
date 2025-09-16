package com.example.security;

import org.springframework.stereotype.Service;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class RateLimitService {
    
    private final ConcurrentHashMap<String, UserRequestInfo> requestCounts = new ConcurrentHashMap<>();
    private final RateLimitConfig config;
    
    public RateLimitService(RateLimitConfig config) {
        this.config = config;
    }
    
    public boolean isAllowed(String clientId) {
        if (!config.isEnabled()) {
            return true;
        }
        
        long currentTime = System.currentTimeMillis();
        
        requestCounts.compute(clientId, (key, userInfo) -> {
            if (userInfo == null || (currentTime - userInfo.windowStart) > config.getTimeWindowMillis()) {
                return new UserRequestInfo(currentTime, new AtomicInteger(1));
            } else {
                userInfo.requestCount.incrementAndGet();
                return userInfo;
            }
        });
        
        UserRequestInfo userInfo = requestCounts.get(clientId);
        return userInfo.requestCount.get() <= config.getMaxRequests();
    }
    
    public int getRemainingRequests(String clientId) {
        UserRequestInfo userInfo = requestCounts.get(clientId);
        if (userInfo == null) {
            return config.getMaxRequests();
        }
        
        long currentTime = System.currentTimeMillis();
        if ((currentTime - userInfo.windowStart) > config.getTimeWindowMillis()) {
            return config.getMaxRequests();
        }
        
        return Math.max(0, config.getMaxRequests() - userInfo.requestCount.get());
    }
    
    public long getResetTime(String clientId) {
        UserRequestInfo userInfo = requestCounts.get(clientId);
        if (userInfo == null) {
            return 0;
        }
        return userInfo.windowStart + config.getTimeWindowMillis();
    }
    
    static class UserRequestInfo {
        final long windowStart;
        final AtomicInteger requestCount;

        UserRequestInfo(long windowStart, AtomicInteger requestCount) {
            this.windowStart = windowStart;
            this.requestCount = requestCount;
        }
    }
}