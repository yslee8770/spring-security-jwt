package com.example.spring_security_jwt.security;


import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(
        String issuer,
        String secret,
        long accessTtlSeconds,
        long refreshTtlSeconds
) { }
