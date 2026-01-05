package com.example.spring_security_jwt.web;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class MeController {

    @GetMapping("/health")
    public String health() {
        return "ok";
    }

    @GetMapping("/me")
    public String me(Authentication authentication) {
        return "hello " + authentication.getName();
    }
}

