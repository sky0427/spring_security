package venus.springboot3.security.domain.member.controller;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import venus.springboot3.security.domain.member.dto.MemberDto;
import venus.springboot3.security.domain.member.service.MemberService;
import venus.springboot3.security.global.custom.CustomOAuth2User;
import venus.springboot3.security.global.util.JwtUtil;

import java.io.IOException;

@Slf4j(topic = "OAuth2Controller")
@RestController
@RequiredArgsConstructor
@RequestMapping("/oauth2")
public class OAuth2Controller {

    private final MemberService memberService;
    private final JwtUtil jwtUtil;

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
        MemberDto memberDto = oAuth2User.getMemberDto();

        String accessToken = jwtUtil.generateAccessToken(memberDto);
        String refreshToken = jwtUtil.generateRefreshToken(memberDto.getEmail());

        jwtUtil.addJwtToCookie(accessToken, response, "accessToken");
        jwtUtil.addJwtToCookie(refreshToken, response, "refreshToken");

        // Redirect url (front)
        response.sendRedirect("http://localhost:8080/api-test");
    }
}
