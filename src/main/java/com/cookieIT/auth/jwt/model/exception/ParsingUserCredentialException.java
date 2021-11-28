package com.cookieIT.auth.jwt.model.exception;

import org.springframework.security.core.AuthenticationException;

public class ParsingUserCredentialException extends AuthenticationException {

    public ParsingUserCredentialException(String msg) {
        super(msg);
    }
}
