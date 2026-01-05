package com.example.spring_security_jwt.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final String token;
    private final Object principal;

    // 인증 전
    public static JwtAuthenticationToken unauthenticated(String token) {
        return new JwtAuthenticationToken(token, null, null);
    }

    // 인증 후
    public static JwtAuthenticationToken authenticated(Object principal, Collection<? extends GrantedAuthority> authorities) {
        return new JwtAuthenticationToken(null, principal, authorities);
    }

    private JwtAuthenticationToken(String token, Object principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.token = token;
        this.principal = principal;
        setAuthenticated(authorities != null);
    }

    public String getToken() { return token; }

    @Override
    public Object getCredentials() { return ""; }

    @Override
    public Object getPrincipal() { return principal; }
}
