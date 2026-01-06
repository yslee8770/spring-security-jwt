package com.example.spring_security_jwt.service;

import java.time.Instant;

public interface BlacklistService {
    void blacklist(String accessToken);
    boolean isBlacklisted(String accessToken);
}
