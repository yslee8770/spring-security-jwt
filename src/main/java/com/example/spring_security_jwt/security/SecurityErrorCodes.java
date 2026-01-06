package com.example.spring_security_jwt.security;

public final class SecurityErrorCodes {
    private SecurityErrorCodes() {}

    public static final String ATTR_AUTH_ERROR_CODE = "AUTH_ERROR_CODE";

    public static final String UNAUTHORIZED = "UNAUTHORIZED";
    public static final String TOKEN_BLACKLISTED = "TOKEN_BLACKLISTED";
}
