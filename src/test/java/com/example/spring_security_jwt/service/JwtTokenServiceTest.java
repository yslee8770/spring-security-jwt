package com.example.spring_security_jwt.service;

import com.example.spring_security_jwt.security.JwtProperties;
import com.example.spring_security_jwt.security.JwtTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
class JwtTokenServiceTest {

    @Autowired
    JwtTokenService tokenService;

    @Autowired
    JwtDecoder jwtDecoder;

    @Autowired
    JwtEncoder jwtEncoder;

    @Autowired
    JwtProperties props;

    @Test
    void mint_access_token_contains_required_claims() {
        // given
        Long userId = 1L;
        String username = "user";
        String[] authorities = {"ROLE_USER", "PERM_REPORT_READ"};

        // when
        JwtTokenService.TokenPair pair = tokenService.mint(userId, username, authorities);
        Jwt jwt = jwtDecoder.decode(pair.accessToken());

        // then (standard claims)
        assertThat(jwt.getSubject()).isEqualTo(username);
        assertThat(jwt.getIssuedAt()).isNotNull();
        assertThat(jwt.getExpiresAt()).isNotNull();
        assertThat(jwt.getId()).isNotBlank(); // jti

        // then (custom claims)
        assertThat(jwt.getClaimAsString("typ")).isEqualTo("access");
        assertThat(numberClaim(jwt, "uid")).isEqualTo(userId);

        List<String> auth = jwt.getClaimAsStringList("auth");
        assertThat(auth).containsExactlyInAnyOrder("ROLE_USER", "PERM_REPORT_READ");

        assertThat(pair.accessExpiresAt()).isNotNull();
    }

    @Test
    void mint_refresh_token_contains_required_claims_and_no_auth() {
        // given
        Long userId = 2L;
        String username = "user2";
        String[] authorities = {"ROLE_USER"};

        // when
        JwtTokenService.TokenPair pair = tokenService.mint(userId, username, authorities);
        Jwt jwt = jwtDecoder.decode(pair.refreshToken());

        // then
        assertThat(jwt.getSubject()).isEqualTo(username);
        assertThat(jwt.getIssuedAt()).isNotNull();
        assertThat(jwt.getExpiresAt()).isNotNull();
        assertThat(jwt.getId()).isNotBlank();

        assertThat(jwt.getClaimAsString("typ")).isEqualTo("refresh");
        assertThat(numberClaim(jwt, "uid")).isEqualTo(userId);

        assertThat(jwt.getClaims()).doesNotContainKey("auth");
        assertThat(jwt.getClaims()).doesNotContainKey("auth");
    }

    @Test
    void decode_expired_token_throws() {
        // given: exp가 과거인 토큰을 직접 생성
        Instant now = Instant.now();
        String expired = encodeCustom(
                now.minusSeconds(7200),
                now.minusSeconds(3600),
                UUID.randomUUID().toString(),
                "expired-user",
                Map.of("uid", 99L, "typ", "access", "auth", new String[]{"ROLE_USER"})
        );

        // when & then
        assertThrows(JwtException.class, () -> jwtDecoder.decode(expired));
    }

    private String encodeCustom(
            Instant issuedAt,
            Instant expiresAt,
            String jti,
            String subject,
            Map<String, Object> claims
    ) {
        JwtClaimsSet claimSet = JwtClaimsSet.builder()
                .issuer(props.issuer())
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .subject(subject)
                .id(jti)
                .claims(m -> m.putAll(claims))
                .build();

        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claimSet)).getTokenValue();
    }

    private static Long numberClaim(Jwt jwt, String name) {
        Object v = jwt.getClaim(name);
        if (v == null) return null;
        if (v instanceof Number n) return n.longValue();
        return Long.parseLong(String.valueOf(v));
    }
}
