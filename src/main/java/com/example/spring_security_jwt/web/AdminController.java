package com.example.spring_security_jwt.web;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AdminController {

    @GetMapping("/admin/ping")
    @PreAuthorize("hasRole('ADMIN')")
    public String ping() {
        return "admin-ok";
    }
}
