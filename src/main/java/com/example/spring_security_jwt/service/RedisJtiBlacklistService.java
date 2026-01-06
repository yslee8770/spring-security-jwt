package com.example.spring_security_jwt.service;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

@Component
@ConditionalOnProperty(name = "app.blacklist.store", havingValue = "redis")
public class RedisJtiBlacklistService implements BlacklistService {

    private static final String KEY_PREFIX = "jwt:blacklist:jti:";

    private final StringRedisTemplate redis;
    private final JwtDecoder jwtDecoder;

    public RedisJtiBlacklistService(StringRedisTemplate redis, JwtDecoder jwtDecoder) {
        this.redis = redis;
        this.jwtDecoder = jwtDecoder;
    }

    @Override
    public void blacklist(String accessToken) {
        try {
            Jwt jwt = jwtDecoder.decode(accessToken);

            String jti = jwt.getId();
            Instant exp = jwt.getExpiresAt();
            if (jti == null || exp == null) return;

            Duration ttl = Duration.between(Instant.now(), exp);
            if (ttl.isZero() || ttl.isNegative()) return;

            redis.opsForValue().set(KEY_PREFIX + jti, "1", ttl);
        } catch (JwtException ignored) {
        }
    }

    @Override
    public boolean isBlacklisted(String accessToken) {
        try {
            Jwt jwt = jwtDecoder.decode(accessToken);
            String jti = jwt.getId();
            if (jti == null) return false;

            Boolean exists = redis.hasKey(KEY_PREFIX + jti);
            return Boolean.TRUE.equals(exists);
        } catch (JwtException ignored) {
            return false;
        }
    }
}
