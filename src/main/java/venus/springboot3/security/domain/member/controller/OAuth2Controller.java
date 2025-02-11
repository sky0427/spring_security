package venus.springboot3.security.domain.member.controller;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import venus.springboot3.security.domain.member.entities.Member;
import venus.springboot3.security.global.custom.CustomOAuth2User;
import venus.springboot3.security.global.util.JwtUtil;

import java.io.IOException;

@Slf4j(topic = "OAuth2Controller")
@Controller
@RequiredArgsConstructor
@RequestMapping("/oauth2")
public class OAuth2Controller {

    private final JwtUtil jwtUtil;

    @Value("${front.redirect-url}")
    private String redirectUrl;

    @GetMapping("/callback/kakao")
    public void kakaoLoginSuccess(Authentication authentication, HttpServletResponse response) throws IOException {
        processOAuth2Login(authentication, response);
    }

    @GetMapping("/callback/naver")
    public void naverLoginSuccess(Authentication authentication, HttpServletResponse response) throws IOException {
        processOAuth2Login(authentication, response);
    }

    private void processOAuth2Login (Authentication authentication, HttpServletResponse response) throws IOException {

        if (authentication == null) {
            log.error("Authentication 객체가 null 입니다.");
            response.sendRedirect("/login?error=authentication_failed"); // 오류 페이지로 리다이렉트
            return;
        }

        CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();
        Member member = oAuth2User.getMember();

        String accessToken = jwtUtil.generateAccessToken(member.getEmail(), member.getRole().name());
        String refreshToken = jwtUtil.generateRefreshToken(member.getEmail());

        jwtUtil.addJwtToCookie(accessToken, response, "accessToken");
        jwtUtil.addJwtToCookie(refreshToken, response, "refreshToken");

        // Redirect url (front)
        response.sendRedirect(redirectUrl);
    }
}
