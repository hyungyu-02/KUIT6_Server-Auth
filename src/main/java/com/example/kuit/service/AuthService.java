package com.example.kuit.service;

import com.example.kuit.dto.response.LoginResponse;
import com.example.kuit.dto.response.ReissueResponse;
import com.example.kuit.jwt.JwtUtil;
import com.example.kuit.model.RefreshToken;
import com.example.kuit.model.Role;
import com.example.kuit.model.User;
import com.example.kuit.repository.RefreshTokenRepository;
import com.example.kuit.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtUtil jwtUtil;

    public LoginResponse login(String username, String password) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("유저가 존재하지 않습니다."));

        if (!user.password().equals(password)) {
            throw new IllegalArgumentException("비밀번호가 일치하지 않습니다.");
        }

        String accessToken = jwtUtil.generateAccessToken(username, user.role().name());
        String refreshToken = jwtUtil.generateRefreshToken(username, user.role().name());

        Instant expiresAt = jwtUtil.getExpiration(refreshToken);
        refreshTokenRepository.deleteByUsername(username);
        RefreshToken tokenToSave = new RefreshToken(username, refreshToken, expiresAt);
        refreshTokenRepository.save(tokenToSave);

        return LoginResponse.of(accessToken, refreshToken);
    }

    public ReissueResponse reissue(String username, Role role, String refreshToken) {
        // DB에 RefreshToken 존재 여부 확인 - refreshTokenRepository.findByUsername 메서드 활용
        RefreshToken dbToken = refreshTokenRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("DB에서 Refresh Token을 찾을 수 없습니다."));

        // DB에 저장되어있는 토큰의 만료 여부 검사 - refresh
        if (dbToken.isExpired()) {
            refreshTokenRepository.deleteByUsername(username);
            throw new IllegalArgumentException("만료된 Refresh Token 입니다.");
        }

        // DB에 저장되어있는 토큰과 요청으로 받은 토큰의 동일 여부 검사
        if (!dbToken.token().equals(refreshToken)) {
            throw new IllegalArgumentException("Refresh Token이 일치하지 않습니다.");
        }

        // AccessToken 재발급
        String newAccessToken = jwtUtil.generateAccessToken(username, role.name());
        return ReissueResponse.of(newAccessToken);
    }
}
