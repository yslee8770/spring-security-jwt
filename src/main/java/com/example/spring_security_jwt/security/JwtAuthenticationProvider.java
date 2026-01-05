package com.example.spring_security_jwt.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final JwtDecoder decoder;

    public JwtAuthenticationProvider(JwtDecoder decoder) {
        this.decoder = decoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) {
        JwtAuthenticationToken token = (JwtAuthenticationToken) authentication;
        Jwt jwt = decoder.decode(token.getToken()); // 위조/만료면 예외

        // claim auth: ["ROLE_USER","PERM_REPORT_READ"] 형태로 저장했다고 가정
        List<String> auth = jwt.getClaimAsStringList("auth");
        var authorities = (auth == null ? List.<SimpleGrantedAuthority>of()
                : auth.stream().map(SimpleGrantedAuthority::new).toList());

        String username = jwt.getSubject();
        return JwtAuthenticationToken.authenticated(username, authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
