package com.example.spring_security_jwt.service;

import com.example.spring_security_jwt.domain.AppUser;
import com.example.spring_security_jwt.domain.RefreshToken;
import com.example.spring_security_jwt.repository.RefreshTokenRepository;
import com.example.spring_security_jwt.repository.UserRepository;
import com.example.spring_security_jwt.security.JwtProperties;
import com.example.spring_security_jwt.security.JwtTokenService;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenService tokenService;
    private final BlacklistService blacklistService;
    private final JwtDecoder jwtDecoder;
    private final JwtProperties jwtProperties;

    public AuthService(AuthenticationManager authenticationManager,
                       UserRepository userRepository,
                       RefreshTokenRepository refreshTokenRepository,
                       JwtTokenService tokenService,
                       BlacklistService blacklistService,
                       JwtDecoder jwtDecoder,
                       JwtProperties jwtProperties
    ) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.tokenService = tokenService;
        this.blacklistService = blacklistService;
        this.jwtDecoder = jwtDecoder;
        this.jwtProperties = jwtProperties;
    }

    @Transactional
    public JwtTokenService.TokenPair login(String username, String password) {
        var auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(username, password)
        );

        AppUser user = userRepository.findByUsername(username).orElseThrow();

        String[] authorities = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toArray(String[]::new);

        var pair = tokenService.mint(user.getId(), username, authorities);

        // refresh 저장(해시)
        var refreshHash = JwtTokenService.sha256Hex(pair.refreshToken());
        // 같은 refreshHash가 있으면 재사용 위험 → unique로 막힘
        refreshTokenRepository.save(new RefreshToken(user.getId(), refreshHash, Instant.now().plusSeconds(jwtProperties.refreshTtlSeconds())));

        return pair;
    }

    @Transactional
    public JwtTokenService.TokenPair refresh(String refreshToken) {
        Jwt jwt = decodeAndValidateRefresh(refreshToken);
        String hash = JwtTokenService.sha256Hex(refreshToken);
        RefreshToken saved = refreshTokenRepository.findByTokenHash(hash).orElseThrow();
        if (saved.isRevoked() || Instant.now().isAfter(saved.getExpiresAt())) {
            throw new IllegalStateException("REFRESH_INVALID");
        }

        Long uid = claimAsLong(jwt, "uid");
        if (uid != null && !uid.equals(saved.getUserId())) {
            throw new IllegalStateException("REFRESH_INVALID");
        }

        saved.revoke();

        AppUser user = userRepository.findById(saved.getUserId()).orElseThrow();
        // refresh로부터 authority를 다시 구성하려면 DB 조회가 필요(여기선 user.roles 기반)
        String[] authorities = user.getRoles().stream()
                .flatMap(r -> java.util.stream.Stream.concat(
                        java.util.stream.Stream.of(r.getName()),
                        r.getPermissions().stream().map(p -> p.getName())
                ))
                .toArray(String[]::new);

        var pair = tokenService.mint(user.getId(), user.getUsername(), authorities);
        refreshTokenRepository.save(new RefreshToken(
                user.getId(),
                JwtTokenService.sha256Hex(pair.refreshToken()),
                Instant.now().plusSeconds(jwtProperties.refreshTtlSeconds())
        ));
        return pair;
    }

    public void logout(String accessToken) {
        blacklistService.blacklist(accessToken);
    }

    private Jwt decodeAndValidateRefresh(String refreshToken) {
        try {
            Jwt jwt = jwtDecoder.decode(refreshToken);
            String typ = jwt.getClaimAsString("typ");
            if (!"refresh".equals(typ)) throw new IllegalStateException("REFRESH_INVALID");
            return jwt;
        } catch (Exception e) {
            throw new IllegalStateException("REFRESH_INVALID");
        }
    }

    private static Long claimAsLong(Jwt jwt, String name) {
        Object v = jwt.getClaim(name);
        if (v == null) return null;
        if (v instanceof Number n) return n.longValue();
        try { return Long.parseLong(String.valueOf(v)); }
        catch (Exception ignore) { return null; }
    }
}