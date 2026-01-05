package com.example.spring_security_jwt.security;

import com.example.spring_security_jwt.service.BlacklistService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.context.SecurityContextHolder; // 핵심 저장소 :contentReference[oaicite:9]{index=9}
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JwtAuthFilter extends OncePerRequestFilter {

    private final AuthenticationManager authenticationManager;
    private final BlacklistService blacklistService;

    public JwtAuthFilter(AuthenticationManager authenticationManager, BlacklistService blacklistService) {
        this.authenticationManager = authenticationManager;
        this.blacklistService = blacklistService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header == null || !header.startsWith("Bearer ")) {
            chain.doFilter(request, response);
            return;
        }

        String raw = header.substring("Bearer ".length()).trim();

        if (blacklistService.isBlacklisted(raw)) {
            SecurityContextHolder.clearContext();
            throw new BadCredentialsException("TOKEN_BLACKLISTED");
        }

        try {
            var auth = authenticationManager.authenticate(JwtAuthenticationToken.unauthenticated(raw));
            SecurityContextHolder.getContext().setAuthentication(auth);
        } catch (Exception ex) {
            SecurityContextHolder.clearContext();
        }

        chain.doFilter(request, response);
    }
}
