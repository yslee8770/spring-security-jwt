package com.example.spring_security_jwt.security;

import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;

@Component
public class JwtTokenService {

    private final JwtEncoder encoder;
    private final JwtProperties props;

    public JwtTokenService(JwtEncoder encoder, JwtProperties props) {
        this.encoder = encoder;
        this.props = props;
    }

    public TokenPair mint(Long userId, String username, String[] authorities) {
        Instant now = Instant.now();

        String jti = UUID.randomUUID().toString();
        String access = encode(now, now.plusSeconds(props.accessTtlSeconds()), jti, username,
                Map.of("uid", userId, "auth", authorities, "typ", "access"));

        // refresh는 별도 jti (회전)
        String rjti = UUID.randomUUID().toString();
        String refresh = encode(now, now.plusSeconds(props.refreshTtlSeconds()), rjti, username,
                Map.of("uid", userId, "typ", "refresh"));

        return new TokenPair(access, refresh, now.plusSeconds(props.accessTtlSeconds()));
    }

    private String encode(Instant issuedAt, Instant expiresAt, String jti, String subject, Map<String, Object> claims) {
        JwtClaimsSet claimSet = JwtClaimsSet.builder()
                .issuer(props.issuer())
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .subject(subject)
                .id(jti)
                .claims(m -> m.putAll(claims))
                .build();

        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return encoder.encode(JwtEncoderParameters.from(header, claimSet)).getTokenValue();
    }

    public static String sha256Hex(String raw) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] out = md.digest(raw.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(out);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public record TokenPair(String accessToken, String refreshToken, Instant accessExpiresAt) { }
}
