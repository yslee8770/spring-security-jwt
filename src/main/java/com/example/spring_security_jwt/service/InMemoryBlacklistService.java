package com.example.spring_security_jwt.service;

import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class InMemoryBlacklistService implements BlacklistService {

    private final Map<String, Instant> store = new ConcurrentHashMap<>();

    @Override
    public void blacklist(String accessToken) {
        store.put(accessToken, Instant.now().plusSeconds(3600));
    }

    @Override
    public boolean isBlacklisted(String accessToken) {
        Instant exp = store.get(accessToken);
        if (exp == null) return false;
        if (Instant.now().isAfter(exp)) {
            store.remove(accessToken);
            return false;
        }
        return true;
    }
}
