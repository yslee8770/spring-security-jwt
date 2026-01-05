package com.example.spring_security_jwt.web.dto;

import java.time.Instant;

public record TokenResponse(
        String accessToken,
        String refreshToken,
        Instant accessExpiresAt
) {}
