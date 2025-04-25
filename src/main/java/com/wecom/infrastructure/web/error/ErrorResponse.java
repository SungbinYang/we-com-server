package com.wecom.infrastructure.web.error;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.wecom.infrastructure.exception.ExceptionCode;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ErrorResponse {

    private String message;

    private HttpStatus status;

    private String code;

    @JsonInclude(JsonInclude.Include.NON_EMPTY)
    private List<ValidationError> errors;

    private LocalDateTime timestamp;

    private ErrorResponse(final ExceptionCode exceptionCode) {
        this.message = exceptionCode.getMessage();
        this.status = exceptionCode.getHttpStatus();
        this.code = exceptionCode.getCode();
        this.timestamp = LocalDateTime.now(ZoneId.of("Asia/Seoul"));
    }

    private ErrorResponse(final ExceptionCode exceptionCode, final String message) {
        this.message = message;
        this.status = exceptionCode.getHttpStatus();
        this.code = exceptionCode.getCode();
        this.timestamp = LocalDateTime.now(ZoneId.of("Asia/Seoul"));
    }

    private ErrorResponse(final ExceptionCode exceptionCode, final List<ValidationError> errors) {
        this.message = exceptionCode.getMessage();
        this.status = exceptionCode.getHttpStatus();
        this.code = exceptionCode.getCode();
        this.timestamp = LocalDateTime.now(ZoneId.of("Asia/Seoul"));
        this.errors = errors;
    }

    public static ErrorResponse of(final ExceptionCode errorCode) {
        return new ErrorResponse(errorCode);
    }

    public static ErrorResponse of(final ExceptionCode errorCode, final String message) {
        return new ErrorResponse(errorCode, message);
    }

    public static ErrorResponse of(final ExceptionCode code, final BindingResult bindingResult) {
        return new ErrorResponse(code, ValidationError.of(bindingResult));
    }

    @Getter
    @NoArgsConstructor(access = AccessLevel.PRIVATE)
    @AllArgsConstructor(access = AccessLevel.PRIVATE)
    private static class ValidationError {

        private String field;

        private String value;

        private String reason;

        public static List<ValidationError> of(final String field, final String value, final String reason) {
            final List<ValidationError> validationErrors = new ArrayList<>();
            validationErrors.add(new ValidationError(field, value, reason));

            return validationErrors;
        }

        public static List<ValidationError> of(final BindingResult bindingResult) {
            final List<FieldError> validationErrors = bindingResult.getFieldErrors();

            return validationErrors.stream()
                    .map(fieldError -> new ValidationError(fieldError.getField(),
                            fieldError.getRejectedValue() == null ? "" : fieldError.getRejectedValue().toString(),
                            fieldError.getDefaultMessage()))
                    .toList();
        }
    }
}
