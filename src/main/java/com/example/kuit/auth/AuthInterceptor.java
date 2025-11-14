package com.example.kuit.auth;

import com.example.kuit.jwt.JwtUtil;
import com.example.kuit.model.Role;
import com.example.kuit.model.TokenType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
@RequiredArgsConstructor
public class AuthInterceptor implements HandlerInterceptor {

    private final JwtUtil jwtUtil;

    // 인증 로직을 인터셉터로 분리
    /**
     * 목적 : 컨트롤러마다 반복되는 인증 코드를 공통 관심사로 분리
     * 해야 할 일
     * 1) Authorization 헤더에서 "Bearer <토큰>" 추출
     * 2) JwtUtil.validate(...) 로 유효성 검사 (만료/위변조 등)
     * 3) 토큰 타입이 ACCESS 인지 확인 (REFRESH 요청은 제외 대상)
     * 4) username/role 을 request attribute 로 저장 (컨트롤러에서 사용)
     * 5) 실패 시 401로 단일화하여 차단
     * -> 참고 : /api/auth/** (login/reissue)는 인터셉터 제외. 별도로 처리할 것
     */
    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        try {
            String token = extractBearer(request);

            if (!jwtUtil.validate(token)) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401
                return false;
            }

            if (jwtUtil.getTokenType(token) != TokenType.ACCESS) {
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // 401
                return false;
            }

            String username = jwtUtil.getUsername(token);
            Role role = jwtUtil.getRole(token);
            request.setAttribute("username", username);
            request.setAttribute("role",  role);

            return true;

        } catch (Exception e) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            return false;
        }

    }

    private String extractBearer(HttpServletRequest request) {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (!StringUtils.hasText(header) || !header.startsWith("Bearer ")) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authorization 헤더 전송 형식이 잘못되었습니다.");
        }
        return header.substring(7);
    }
}
