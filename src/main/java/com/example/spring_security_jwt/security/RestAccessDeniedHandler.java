package com.example.spring_security_jwt.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import com.example.spring_security_jwt.web.dto.ErrorResponse;

import java.io.IOException;

public class RestAccessDeniedHandler implements AccessDeniedHandler {

    private final ObjectMapper om = new ObjectMapper();

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException)
            throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        om.writeValue(response.getWriter(), new ErrorResponse("FORBIDDEN", "Access denied"));
    }
}
