package com.example.spring_security_jwt.service;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class ReportService {

    @PreAuthorize("hasAuthority('PERM_REPORT_READ')")
    public String summary() {
        return "report-ok";
    }
}
