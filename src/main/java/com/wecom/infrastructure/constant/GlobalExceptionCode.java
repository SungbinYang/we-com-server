package com.wecom.infrastructure.constant;

import com.wecom.infrastructure.exception.ExceptionCode;
import com.wecom.infrastructure.type.EnumType;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;

import static org.springframework.http.HttpStatus.*;

@Getter
@RequiredArgsConstructor
public enum GlobalExceptionCode implements EnumType, ExceptionCode {

    // 클라이언트 오류 (400 계열)
    INVALID_REQUEST_PARAMETER(BAD_REQUEST, "C400-01", "유효하지 않은 요청 파라미터입니다.", "400-01 에러 코드입니다."),
    INVALID_REQUEST_BODY(BAD_REQUEST, "C400-02", "유효하지 않은 요청 본문입니다.", "400-02 에러 코드입니다."),
    MISSING_REQUIRED_FIELD(BAD_REQUEST, "C400-03", "필수 필드가 누락되었습니다.", "400-03 에러 코드입니다."),
    INVALID_INPUT_FORMAT(BAD_REQUEST, "C400-04", "입력 형식이 올바르지 않습니다.", "400-04 에러 코드입니다."),
    DATA_INTEGRITY_VIOLATION(BAD_REQUEST, "C400-05", "데이터 무결성 위반이 발생했습니다.", "400-05 에러 코드입니다."),
    REQUEST_SIZE_EXCEEDED(BAD_REQUEST, "C400-06", "요청 크기가 제한을 초과했습니다.", "400-06 에러 코드입니다."),
    UNSUPPORTED_MEDIA_TYPE(BAD_REQUEST, "C400-07", "지원하지 않는 미디어 타입입니다.", "400-07 에러 코드입니다."),

    // 인증/인가 오류 (401, 403 계열)
    UNAUTHORIZED_RESOURCE_OWNER(UNAUTHORIZED, "A401-01", "해당 리소스를 처리를 하기 위한 인증정보가 없습니다.", "401-01 에러 코드"),
    INVALID_TOKEN(UNAUTHORIZED, "A401-02", "유효하지 않은 인증 토큰입니다.", "401-02 에러 코드"),
    TOKEN_EXPIRED(UNAUTHORIZED, "A401-03", "인증 토큰이 만료되었습니다.", "401-03 에러 코드"),
    INVALID_CREDENTIALS(UNAUTHORIZED, "A401-04", "잘못된 로그인 정보입니다.", "401-04 에러 코드"),
    MISSING_TOKEN(UNAUTHORIZED, "A401-05", "인증 토큰이 제공되지 않았습니다.", "401-05 에러 코드"),
    TOKEN_SIGNATURE_INVALID(UNAUTHORIZED, "A401-06", "토큰 서명이 유효하지 않습니다.", "401-06 에러 코드"),

    INVALID_RESOURCE_OWNER(FORBIDDEN, "A403-01", "해당 리소스를 처리할 인증정보는 있으나 권한이 없습니다.", "403-01 에러 코드"),
    INSUFFICIENT_PERMISSIONS(FORBIDDEN, "A403-02", "해당 작업을 수행할 권한이 부족합니다.", "403-02 에러 코드"),
    ACCESS_LIMIT_EXCEEDED(FORBIDDEN, "A403-03", "접근 제한 횟수를 초과했습니다.", "403-03 에러 코드"),

    // 리소스 오류 (404 계열)
    NOT_FOUND_RESOURCE(NOT_FOUND, "R404-01", "해당 리소스를 찾을 수 없습니다.", "404-01 에러 코드"),
    ENDPOINT_NOT_FOUND(NOT_FOUND, "R404-02", "요청한 엔드포인트를 찾을 수 없습니다.", "404-02 에러 코드"),

    // 메소드 오류 (405 계열)
    INVALID_REQUEST_METHOD(METHOD_NOT_ALLOWED, "M405-01", "유효하지 않은 HTTP 요청 메소드입니다.", "405-01 에러 코드"),

    // 충돌 오류 (409 계열)
    RESOURCE_CONFLICT(CONFLICT, "C409-01", "리소스 충돌이 발생했습니다.", "409-01 에러 코드"),
    CONCURRENT_MODIFICATION(CONFLICT, "C409-02", "동시 수정으로 인한 충돌이 발생했습니다.", "409-02 에러 코드"),
    VERSION_CONFLICT(CONFLICT, "C409-03", "리소스 버전 충돌이 발생했습니다.", "409-03 에러 코드"),
    DUPLICATE_RESOURCE(CONFLICT, "C409-04", "이미 존재하는 리소스입니다.", "409-04 에러 코드"),

    // 데이터 처리 오류 (422 계열)
    UNPROCESSABLE_REQUEST(UNPROCESSABLE_ENTITY, "C422-01", "요청을 처리할 수 없습니다.", "422-01 에러 코드"),
    VALIDATION_FAILED(UNPROCESSABLE_ENTITY, "C422-02", "데이터 유효성 검사에 실패했습니다.", "422-02 에러 코드"),
    BUSINESS_RULE_VIOLATION(UNPROCESSABLE_ENTITY, "C422-03", "비즈니스 규칙 위반이 발생했습니다.", "422-03 에러 코드"),

    // 서버 오류 (500 계열)
    SERVER_ERROR(INTERNAL_SERVER_ERROR, "S500-01", "Internal Server Error", "500-01 에러 코드"),
    DATABASE_ERROR(INTERNAL_SERVER_ERROR, "S500-02", "데이터베이스 오류가 발생했습니다.", "500-02 에러 코드"),
    EXTERNAL_API_ERROR(INTERNAL_SERVER_ERROR, "S500-03", "외부 API 호출 중 오류가 발생했습니다.", "500-03 에러 코드"),
    UNEXPECTED_ERROR(INTERNAL_SERVER_ERROR, "S500-04", "예상치 못한 오류가 발생했습니다.", "500-04 에러 코드"),
    FILE_PROCESSING_ERROR(INTERNAL_SERVER_ERROR, "S500-05", "파일 처리 중 오류가 발생했습니다.", "500-05 에러 코드"),
    INTEGRATION_ERROR(INTERNAL_SERVER_ERROR, "S500-06", "외부 시스템 연동 중 오류가 발생했습니다.", "500-06 에러 코드"),

    // 서비스 사용 불가 오류 (503 계열)
    SERVICE_UNAVAILABLE_NOW(SERVICE_UNAVAILABLE, "S503-01", "서비스를 일시적으로 사용할 수 없습니다.", "503-01 에러 코드"),
    MAINTENANCE_MODE(SERVICE_UNAVAILABLE, "S503-02", "시스템이 유지보수 모드입니다.", "503-02 에러 코드"),
    RATE_LIMIT_EXCEEDED(SERVICE_UNAVAILABLE, "S503-03", "요청 비율 제한을 초과했습니다.", "503-03 에러 코드"),

    // 게이트웨이 오류 (504 계열)
    TIMEOUT(GATEWAY_TIMEOUT, "S504-01", "게이트웨이 시간 초과가 발생했습니다.", "504-01 에러 코드");

    private final HttpStatus httpStatus;

    private final String code;

    private final String message;

    private final String description;
}
