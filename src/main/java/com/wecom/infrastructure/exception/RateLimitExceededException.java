package com.wecom.infrastructure.exception;

public class RateLimitExceededException extends IllegalStateException {
    public RateLimitExceededException(String message) {
        super(message);
    }
}
