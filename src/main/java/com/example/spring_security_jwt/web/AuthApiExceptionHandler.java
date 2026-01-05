package com.example.spring_security_jwt.web;

import com.example.spring_security_jwt.web.dto.ErrorResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class AuthApiExceptionHandler {

    @ExceptionHandler(AuthenticationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ErrorResponse authenticationFailed(AuthenticationException e) {
        return new ErrorResponse("AUTH_FAILED", "Authentication failed");
    }

    @ExceptionHandler(IllegalStateException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public ErrorResponse illegalState(IllegalStateException e) {
        if ("REFRESH_INVALID".equals(e.getMessage())) {
            return new ErrorResponse("REFRESH_INVALID", "Refresh token is invalid");
        }
        return new ErrorResponse("INVALID_STATE", e.getMessage());
    }
}
