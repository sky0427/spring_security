package venus.springboot3.security.global.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import venus.springboot3.security.domain.member.dto.LoginRequestDto;
import venus.springboot3.security.domain.member.entities.Member;
import venus.springboot3.security.global.custom.CustomUserDetails;
import venus.springboot3.security.global.util.JwtUtil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

// 일반 로그인 요청 (/api/member/login)을 처리하는 필터
// 인증에 성공한 후, JWT 를 생성하는데 필요한 사용자 정보는 CustomUserDetails 객체를 통해 전달
@Slf4j(topic = "JwtAuthenticationFilter")
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    public JwtAuthenticationFilter(JwtUtil jwtUtil, AuthenticationManager authenticationManager) {
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
        setFilterProcessesUrl("/api/member/login"); // 로그인 요청 URL
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        if (!request.getMethod().equals("POST")) {
            throw new AuthenticationServiceException("Authentication method not supported: " + request.getMethod());
        }

        try {
            LoginRequestDto loginRequestDto = new ObjectMapper().readValue(request.getInputStream(), LoginRequestDto.class);

            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                    loginRequestDto.getEmail(),
                    loginRequestDto.getPassword(),
                    Collections.emptyList() // 권한 정보는 JWT 에서 관리하므로 빈 리스트 전달
            );

            setAuthenticationManager(authenticationManager);
            return getAuthenticationManager().authenticate(authenticationToken);
        } catch (IOException e) {
            log.error("RequestBody 를 읽는 데 실패하였습니다.", e);
            throw new AuthenticationServiceException("RequestBody 를 읽는 데 실패하였습니다.");
        }
    }

    @Override
    protected void successfulAuthentication (HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        CustomUserDetails userDetails = (CustomUserDetails) authResult.getPrincipal();
        Member member = userDetails.getMember();

        String accessToken = jwtUtil.generateAccessToken(member.getEmail(), member.getRole().name());
        String refreshToken = jwtUtil.generateRefreshToken(member.getEmail());

        jwtUtil.addJwtToCookie(accessToken, response, "accessToken");
        jwtUtil.addJwtToCookie(refreshToken, response, "refreshToken");

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write("{\"message\": \"로그인 성공\"}");
    }

    @Override
    protected void unsuccessfulAuthentication (HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setCharacterEncoding(StandardCharsets.UTF_8.name());
        response.getWriter().write("{\"message\": \"로그인 실패\"}");
    }
}
