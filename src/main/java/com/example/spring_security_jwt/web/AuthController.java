package com.example.spring_security_jwt.web;


import com.example.spring_security_jwt.service.AuthService;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.web.bind.annotation.*;
import com.example.spring_security_jwt.web.dto.LoginRequest;
import com.example.spring_security_jwt.web.dto.RefreshRequest;
import com.example.spring_security_jwt.web.dto.TokenResponse;

@RestController
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/auth/login")
    public TokenResponse login(@RequestBody @Valid LoginRequest req) {
        var pair = authService.login(req.username(), req.password());
        return new TokenResponse(pair.accessToken(), pair.refreshToken(), pair.accessExpiresAt());
    }

    @PostMapping("/auth/refresh")
    public TokenResponse refresh(@RequestBody @Valid RefreshRequest req) {
        var pair = authService.refresh(req.refreshToken());
        return new TokenResponse(pair.accessToken(), pair.refreshToken(), pair.accessExpiresAt());
    }

    @PostMapping("/auth/logout")
    public void logout(@RequestHeader(HttpHeaders.AUTHORIZATION) String authHeader) {
        String token = authHeader.substring("Bearer ".length()).trim();
        authService.logout(token);
    }
}
