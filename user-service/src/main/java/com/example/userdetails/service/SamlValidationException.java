package com.example.userdetails.service;

public class SamlValidationException extends RuntimeException {
    public SamlValidationException(String message) {
        super(message);
    }

    public SamlValidationException(String message, Throwable cause) {
        super(message, cause);
    }
}
