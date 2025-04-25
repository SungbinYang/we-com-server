package com.wecom.infrastructure.exception;

import com.wecom.infrastructure.web.error.ErrorResponse;
import jakarta.persistence.EntityNotFoundException;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.data.mapping.PropertyReferenceException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.*;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.rememberme.CookieTheftException;
import org.springframework.security.web.authentication.rememberme.InvalidCookieException;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.validation.BindException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.context.request.async.AsyncRequestTimeoutException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.servlet.NoHandlerFoundException;

import java.io.IOException;
import java.net.ConnectException;
import java.sql.SQLException;
import java.util.NoSuchElementException;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeoutException;

import static com.wecom.infrastructure.constant.GlobalExceptionCode.*;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * INVALID_REQUEST_PARAMETER (C400-01) 처리
     * 메소드 인자 유효성 검증 실패 시 발생
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    protected ResponseEntity<ErrorResponse> handleMethodArgumentNotValidException(MethodArgumentNotValidException e) {
        log.error("유효하지 않은 요청 파라미터: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(INVALID_REQUEST_PARAMETER, "요청 파라미터가 유효하지 않습니다."),
                INVALID_REQUEST_PARAMETER.getHttpStatus()
        );
    }

    /**
     * INVALID_REQUEST_PARAMETER (C400-01) 처리
     * 바인딩 실패 시 발생
     */
    @ExceptionHandler(BindException.class)
    protected ResponseEntity<ErrorResponse> handleBindException(BindException e) {
        log.error("바인딩 실패: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(INVALID_REQUEST_PARAMETER, "바인딩에 실패하였습니다."),
                INVALID_REQUEST_PARAMETER.getHttpStatus()
        );
    }

    /**
     * VALIDATION_FAILED (C422-02) 처리
     * 제약 조건 위반 시 발생
     */
    @ExceptionHandler(ConstraintViolationException.class)
    protected ResponseEntity<ErrorResponse> handleConstraintViolationException(ConstraintViolationException e) {
        log.error("제약 조건 위반: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(VALIDATION_FAILED, "요청 데이터가 유효성 규칙을 위반했습니다."),
                VALIDATION_FAILED.getHttpStatus()
        );
    }

    /**
     * INVALID_INPUT_FORMAT (C400-04) 처리
     * 메소드 인자 타입 불일치 시 발생
     */
    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    protected ResponseEntity<ErrorResponse> handleMethodArgumentTypeMismatchException(MethodArgumentTypeMismatchException e) {
        log.error("메소드 인자 타입 불일치: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(INVALID_INPUT_FORMAT, "요청 파라미터 형식이 올바르지 않습니다."),
                INVALID_INPUT_FORMAT.getHttpStatus()
        );
    }

    /**
     * REQUEST_SIZE_EXCEEDED (C400-06) 처리
     * 파일 업로드 크기 초과 시 발생
     */
    @ExceptionHandler(MaxUploadSizeExceededException.class)
    protected ResponseEntity<ErrorResponse> handleMaxUploadSizeExceededException(MaxUploadSizeExceededException e) {
        log.error("파일 업로드 크기 초과: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(REQUEST_SIZE_EXCEEDED, "파일 크기가 제한을 초과했습니다."),
                REQUEST_SIZE_EXCEEDED.getHttpStatus()
        );
    }

    /**
     * BUSINESS_RULE_VIOLATION (C422-03) 처리
     * 비즈니스 규칙 위반 시 발생
     */
    @ExceptionHandler(BusinessException.class)
    protected ResponseEntity<ErrorResponse> handleBusinessException(BusinessException e) {
        log.error("비즈니스 규칙 위반: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(BUSINESS_RULE_VIOLATION, "비즈니스 규칙 위반이 발생했습니다."),
                BUSINESS_RULE_VIOLATION.getHttpStatus()
        );
    }

    /**
     * INVALID_REQUEST_BODY (C400-02) 처리
     * HTTP 메시지 본문 파싱 실패 시 발생
     */
    @ExceptionHandler(HttpMessageNotReadableException.class)
    protected ResponseEntity<ErrorResponse> handleHttpMessageNotReadableException(HttpMessageNotReadableException e) {
        log.error("HTTP 메시지 본문 파싱 실패: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(INVALID_REQUEST_BODY, "요청 본문을 읽을 수 없습니다. 올바른 JSON 형식인지 확인하세요."),
                INVALID_REQUEST_BODY.getHttpStatus()
        );
    }

    /**
     * MISSING_REQUIRED_FIELD (C400-03) 처리
     * 필수 요청 파라미터 누락 시 발생
     */
    @ExceptionHandler(MissingServletRequestParameterException.class)
    protected ResponseEntity<ErrorResponse> handleMissingServletRequestParameterException(MissingServletRequestParameterException e) {
        log.error("필수 요청 파라미터 누락: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(MISSING_REQUIRED_FIELD, "필수 파라미터 '" + e.getParameterName() + "'가 누락되었습니다."),
                MISSING_REQUIRED_FIELD.getHttpStatus()
        );
    }

    /**
     * UNSUPPORTED_MEDIA_TYPE (C400-07) 처리
     * 지원하지 않는 미디어 타입 요청 시 발생
     */
    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    protected ResponseEntity<ErrorResponse> handleHttpMediaTypeNotSupportedException(HttpMediaTypeNotSupportedException e) {
        log.error("지원하지 않는 미디어 타입: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(UNSUPPORTED_MEDIA_TYPE, "지원하지 않는 미디어 타입입니다: " + e.getContentType()),
                UNSUPPORTED_MEDIA_TYPE.getHttpStatus()
        );
    }

    /**
     * DATA_INTEGRITY_VIOLATION (C400-05) 처리
     * 데이터 무결성 위반 시 발생
     */
    @ExceptionHandler(DataIntegrityViolationException.class)
    protected ResponseEntity<ErrorResponse> handleDataIntegrityViolationException(DataIntegrityViolationException e) {
        log.error("데이터 무결성 위반: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(DATA_INTEGRITY_VIOLATION, "데이터 무결성 위반이 발생했습니다."),
                DATA_INTEGRITY_VIOLATION.getHttpStatus()
        );
    }

    /**
     * UNAUTHORIZED_RESOURCE_OWNER (A401-01) 처리
     * 인증 실패 시 발생
     */
    @ExceptionHandler(AuthenticationException.class)
    protected ResponseEntity<ErrorResponse> handleAuthenticationException(AuthenticationException e) {
        log.error("인증 실패: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(UNAUTHORIZED_RESOURCE_OWNER, "인증에 실패했습니다."),
                UNAUTHORIZED_RESOURCE_OWNER.getHttpStatus()
        );
    }

    /**
     * INVALID_CREDENTIALS (A401-04) 처리
     * 잘못된 인증 정보 제공 시 발생
     */
    @ExceptionHandler(BadCredentialsException.class)
    protected ResponseEntity<ErrorResponse> handleBadCredentialsException(BadCredentialsException e) {
        log.error("잘못된 인증 정보: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(INVALID_CREDENTIALS, "아이디 또는 비밀번호가 일치하지 않습니다."),
                INVALID_CREDENTIALS.getHttpStatus()
        );
    }

    /**
     * INVALID_TOKEN (A401-02) 처리
     * 유효하지 않은 쿠키 또는 토큰
     */
    @ExceptionHandler({InvalidCookieException.class, CookieTheftException.class, InvalidCsrfTokenException.class})
    protected ResponseEntity<ErrorResponse> handleInvalidTokenException(Exception e) {
        log.error("유효하지 않은 토큰: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(INVALID_TOKEN, "유효하지 않은 인증 토큰입니다."),
                INVALID_TOKEN.getHttpStatus()
        );
    }

    /**
     * TOKEN_EXPIRED (A401-03) 처리
     * 토큰 만료 시 발생
     */
    @ExceptionHandler(CredentialsExpiredException.class)
    protected ResponseEntity<ErrorResponse> handleCredentialsExpiredException(CredentialsExpiredException e) {
        log.error("토큰 만료: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(TOKEN_EXPIRED, "인증 토큰이 만료되었습니다."),
                TOKEN_EXPIRED.getHttpStatus()
        );
    }

    /**
     * MISSING_TOKEN (A401-05) 처리
     * 토큰 누락 시 발생
     */
    @ExceptionHandler(MissingCsrfTokenException.class)
    protected ResponseEntity<ErrorResponse> handleMissingCsrfTokenException(MissingCsrfTokenException e) {
        log.error("토큰 누락: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(MISSING_TOKEN, "인증 토큰이 제공되지 않았습니다."),
                MISSING_TOKEN.getHttpStatus()
        );
    }

    /**
     * ACCESS_LIMIT_EXCEEDED (A403-03) 처리
     * 계정 잠금 시 발생
     */
    @ExceptionHandler(LockedException.class)
    protected ResponseEntity<ErrorResponse> handleLockedException(LockedException e) {
        log.error("계정 잠금: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(ACCESS_LIMIT_EXCEEDED, "접근 제한 횟수를 초과했습니다."),
                ACCESS_LIMIT_EXCEEDED.getHttpStatus()
        );
    }

    /**
     * INSUFFICIENT_PERMISSIONS (A403-02) 처리
     * 불충분한 인증 시 발생
     */
    @ExceptionHandler(InsufficientAuthenticationException.class)
    protected ResponseEntity<ErrorResponse> handleInsufficientAuthenticationException(InsufficientAuthenticationException e) {
        log.error("불충분한 인증: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(INSUFFICIENT_PERMISSIONS, "인증 정보가 없거나 불충분합니다."),
                INSUFFICIENT_PERMISSIONS.getHttpStatus()
        );
    }

    /**
     * INVALID_RESOURCE_OWNER (A403-01) 처리
     * 접근 권한 부족 시 발생
     */
    @ExceptionHandler(AccessDeniedException.class)
    protected ResponseEntity<ErrorResponse> handleAccessDeniedException(AccessDeniedException e) {
        log.error("접근 권한 부족: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(INVALID_RESOURCE_OWNER, "해당 리소스에 접근할 권한이 없습니다."),
                INVALID_RESOURCE_OWNER.getHttpStatus()
        );
    }

    /**
     * INSUFFICIENT_PERMISSIONS (A403-02) 처리
     * 계정 비활성화 시 발생
     */
    @ExceptionHandler(DisabledException.class)
    protected ResponseEntity<ErrorResponse> handleDisabledException(DisabledException e) {
        log.error("계정 비활성화: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(INSUFFICIENT_PERMISSIONS, "비활성화된 계정입니다."),
                INSUFFICIENT_PERMISSIONS.getHttpStatus()
        );
    }

    /**
     * NOT_FOUND_RESOURCE (R404-01) 처리
     * 요소를 찾을 수 없을 때 발생
     */
    @ExceptionHandler(NoSuchElementException.class)
    protected ResponseEntity<ErrorResponse> handleNoSuchElementException(NoSuchElementException e) {
        log.error("요소를 찾을 수 없음: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(NOT_FOUND_RESOURCE, "요청한 리소스를 찾을 수 없습니다."),
                NOT_FOUND_RESOURCE.getHttpStatus()
        );
    }

    /**
     * NOT_FOUND_RESOURCE (R404-01) 처리
     * 엔티티를 찾을 수 없을 때 발생
     */
    @ExceptionHandler(EntityNotFoundException.class)
    protected ResponseEntity<ErrorResponse> handleEntityNotFoundException(EntityNotFoundException e) {
        log.error("엔티티를 찾을 수 없음: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(NOT_FOUND_RESOURCE, "요청한 엔티티를 찾을 수 없습니다."),
                NOT_FOUND_RESOURCE.getHttpStatus()
        );
    }

    /**
     * NOT_FOUND_RESOURCE (R404-01) 처리
     * JPA 속성 참조 오류 시 발생
     */
    @ExceptionHandler(PropertyReferenceException.class)
    protected ResponseEntity<ErrorResponse> handlePropertyReferenceException(PropertyReferenceException e) {
        log.error("JPA 속성 참조 오류: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(NOT_FOUND_RESOURCE, "잘못된 속성 참조가 발생했습니다."),
                NOT_FOUND_RESOURCE.getHttpStatus()
        );
    }

    /**
     * ENDPOINT_NOT_FOUND (R404-02) 처리
     * 요청한 엔드포인트가 없을 때 발생
     */
    @ExceptionHandler(NoHandlerFoundException.class)
    protected ResponseEntity<ErrorResponse> handleNoHandlerFoundException(NoHandlerFoundException e) {
        log.error("엔드포인트를 찾을 수 없음: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(ENDPOINT_NOT_FOUND, "요청을 처리할 수 없습니다."),
                ENDPOINT_NOT_FOUND.getHttpStatus()
        );
    }

    /**
     * INVALID_REQUEST_METHOD (M405-01) 처리
     * 지원하지 않는 HTTP 메소드 요청 시 발생
     */
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    protected ResponseEntity<ErrorResponse> handleHttpRequestMethodNotSupportedException(HttpRequestMethodNotSupportedException e) {
        log.error("지원하지 않는 HTTP 메소드: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(INVALID_REQUEST_METHOD, "지원하지 않는 HTTP 메소드입니다."),
                INVALID_REQUEST_METHOD.getHttpStatus()
        );
    }

    /**
     * RESOURCE_CONFLICT (C409-01) 처리
     * 리소스 충돌 발생 시
     */
    @ExceptionHandler(DuplicateKeyException.class)
    protected ResponseEntity<ErrorResponse> handleDuplicateKeyException(DuplicateKeyException e) {
        log.error("중복 키 오류: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(DUPLICATE_RESOURCE, "이미 존재하는 리소스입니다."),
                DUPLICATE_RESOURCE.getHttpStatus()
        );
    }

    /**
     * CONCURRENT_MODIFICATION (C409-02) 처리
     * 낙관적 락킹 실패 시 발생
     */
    @ExceptionHandler(OptimisticLockingFailureException.class)
    protected ResponseEntity<ErrorResponse> handleOptimisticLockingFailureException(OptimisticLockingFailureException e) {
        log.error("낙관적 락킹 실패: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(CONCURRENT_MODIFICATION, "다른 사용자가 해당 리소스를 수정했습니다. 다시 시도해주세요."),
                CONCURRENT_MODIFICATION.getHttpStatus()
        );
    }

    /**
     * VERSION_CONFLICT (C409-03) 처리
     * 버전 충돌 시 발생
     */
    @ExceptionHandler(SQLException.class)
    protected ResponseEntity<ErrorResponse> handleSQLException(SQLException e) {
        String sqlState = e.getSQLState();

        if ("23000".equals(sqlState) || "40001".equals(sqlState)) {
            log.error("버전 충돌: ", e);
            return new ResponseEntity<>(
                    ErrorResponse.of(VERSION_CONFLICT, "리소스 버전 충돌이 발생했습니다."),
                    VERSION_CONFLICT.getHttpStatus()
            );
        }
        return handleDatabaseException(e);
    }

    /**
     * UNPROCESSABLE_ENTITY (C422-01) 처리
     * 요청을 처리할 수 없음
     */
    @ExceptionHandler(UnsupportedOperationException.class)
    protected ResponseEntity<ErrorResponse> handleUnsupportedOperationException(UnsupportedOperationException e) {
        log.error("지원하지 않는 연산: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(UNPROCESSABLE_REQUEST, "요청을 처리할 수 없습니다: " + e.getMessage()),
                UNPROCESSABLE_REQUEST.getHttpStatus()
        );
    }

    /**
     * DATABASE_ERROR (S500-02) 처리
     * 데이터 액세스 오류 시 발생
     */
    @ExceptionHandler(DataAccessException.class)
    protected ResponseEntity<ErrorResponse> handleDataAccessException(DataAccessException e) {
        log.error("데이터 액세스 오류: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(DATABASE_ERROR, "데이터베이스 오류가 발생했습니다."),
                DATABASE_ERROR.getHttpStatus()
        );
    }

    /**
     * DATABASE_ERROR (S500-02) 처리
     * 데이터베이스 예외 처리
     */
    protected ResponseEntity<ErrorResponse> handleDatabaseException(Exception e) {
        log.error("데이터베이스 오류: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(DATABASE_ERROR, "데이터베이스 오류가 발생했습니다."),
                DATABASE_ERROR.getHttpStatus()
        );
    }

    /**
     * EXTERNAL_API_ERROR (S500-03) 처리
     * 외부 API 호출 오류 시 발생
     */
    @ExceptionHandler(RestClientException.class)
    protected ResponseEntity<ErrorResponse> handleRestClientException(RestClientException e) {
        log.error("외부 API 호출 오류: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(EXTERNAL_API_ERROR, "외부 API 호출 중 오류가 발생했습니다."),
                EXTERNAL_API_ERROR.getHttpStatus()
        );
    }

    /**
     * FILE_PROCESSING_ERROR (S500-05) 처리
     * 파일 처리 오류 시 발생
     */
    @ExceptionHandler(IOException.class)
    protected ResponseEntity<ErrorResponse> handleIOException(IOException e) {
        log.error("파일 처리 오류: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(FILE_PROCESSING_ERROR, "파일 처리 중 오류가 발생했습니다."),
                FILE_PROCESSING_ERROR.getHttpStatus()
        );
    }

    /**
     * INTEGRATION_ERROR (S500-06) 처리
     * 외부 시스템 연동 오류
     */
    @ExceptionHandler(ConnectException.class)
    protected ResponseEntity<ErrorResponse> handleConnectException(ConnectException e) {
        log.error("연결 오류: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(INTEGRATION_ERROR, "외부 시스템 연동 중 오류가 발생했습니다."),
                INTEGRATION_ERROR.getHttpStatus()
        );
    }

    /**
     * SERVICE_UNAVAILABLE (S503-01) 처리
     * 서비스 일시적 사용 불가
     */
    @ExceptionHandler(RejectedExecutionException.class)
    protected ResponseEntity<ErrorResponse> handleRejectedExecutionException(RejectedExecutionException e) {
        log.error("작업 거부: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(SERVICE_UNAVAILABLE_NOW, "서비스를 일시적으로 사용할 수 없습니다."),
                SERVICE_UNAVAILABLE_NOW.getHttpStatus()
        );
    }

    /**
     * RATE_LIMIT_EXCEEDED (S503-03) 처리
     * 요청 비율 제한 초과
     */
    @ExceptionHandler(IllegalStateException.class)
    protected ResponseEntity<ErrorResponse> handleIllegalStateException(IllegalStateException e) {
        if (e instanceof RateLimitExceededException) {
            log.error("비율 제한 초과: ", e);
            return new ResponseEntity<>(
                    ErrorResponse.of(RATE_LIMIT_EXCEEDED, "요청 비율 제한을 초과했습니다."),
                    RATE_LIMIT_EXCEEDED.getHttpStatus()
            );
        }
        return handleException(e);
    }

    /**
     * GATEWAY_TIMEOUT (S504-01) 처리
     * 리소스 접근 시간 초과 시 발생
     */
    @ExceptionHandler({ResourceAccessException.class, TimeoutException.class, AsyncRequestTimeoutException.class})
    protected ResponseEntity<ErrorResponse> handleTimeoutException(Exception e) {
        log.error("시간 초과: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(TIMEOUT, "외부 서비스 응답 시간이 초과되었습니다."),
                TIMEOUT.getHttpStatus()
        );
    }

    /**
     * UNEXPECTED_ERROR (S500-04) 처리
     * 예상치 못한 오류 발생
     */
    @ExceptionHandler(RuntimeException.class)
    protected ResponseEntity<ErrorResponse> handleRuntimeException(RuntimeException e) {
        log.error("예상치 못한 런타임 오류: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(UNEXPECTED_ERROR, "예상치 못한 오류가 발생했습니다."),
                UNEXPECTED_ERROR.getHttpStatus()
        );
    }

    /**
     * SERVER_ERROR (S500-01) 처리
     * 기타 모든 예외 처리
     */
    @ExceptionHandler(Exception.class)
    protected ResponseEntity<ErrorResponse> handleException(Exception e) {
        log.error("서버 오류: ", e);
        return new ResponseEntity<>(
                ErrorResponse.of(SERVER_ERROR, "서버 내부 오류가 발생했습니다."),
                SERVER_ERROR.getHttpStatus()
        );
    }
}
