package com.wecom.infrastructure.web.success;

import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor(access = AccessLevel.PROTECTED)
public class SuccessCommonApiResponse {

    private final String message;

    public static SuccessCommonApiResponse of(final String message) {
        return new SuccessCommonApiResponse(message);
    }
}
