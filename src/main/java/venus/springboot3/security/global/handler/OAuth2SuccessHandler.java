package venus.springboot3.security.global.handler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import venus.springboot3.security.domain.member.entities.Member;
import venus.springboot3.security.global.custom.CustomOAuth2User;
import venus.springboot3.security.global.util.JwtUtil;

import java.io.IOException;

@Slf4j(topic = "OAuth2SuccessHandler")
@Component
@RequiredArgsConstructor
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtUtil jwtUtil;

    @Value("${front.redirect-url}")
    private String redirectUrl;

    @Override
    public void onAuthenticationSuccess (HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        try {
            CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();
            Member member = oAuth2User.getMember();
            log.info("OAuth2SuccessHandler에서 정상적으로 객체를 가져왔습니다. {}", member);

            String accessToken = jwtUtil.generateAccessToken(member.getEmail(), member.getRole().name());
            String refreshToken = jwtUtil.generateRefreshToken(member.getEmail());

            jwtUtil.addJwtToCookie(accessToken, response, "accessToken");
            jwtUtil.addJwtToCookie(refreshToken, response, "refreshToken");

            log.info("OAuth2SuccessHandler에서 정상적으로 accessToken과 RefreshToken을 생성 및 쿠키에 저장하였습니다.");

            response.sendRedirect(redirectUrl);

        } catch (Exception e) {
            log.error("OAuth2 인증 성공 후 처리 중 오류 발생: {}", e.getMessage(), e);
            throw new ServletException("OAuth2 인증 성공 후 처리 중 오류 발생", e);
        }
    }
}
