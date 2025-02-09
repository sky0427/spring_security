package venus.springboot3.security.global.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import venus.springboot3.security.domain.member.dto.LoginRequestDto;
import venus.springboot3.security.domain.member.dto.MemberDto;
import venus.springboot3.security.global.custom.CustomUserDetails;
import venus.springboot3.security.global.util.JwtUtil;

import java.io.IOException;
import java.util.Collections;

// 일반 로그인 요청 (/api/member/login)을 처리하는 필터
// 인증에 성공한 후, JWT 를 생성하는데 필요한 사용자 정보는 CustomUserDetails 객체를 통해 전달
@Slf4j(topic = "JwtAuthenticationFilter")
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final JwtUtil jwtUtil;

    public JwtAuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
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

            return getAuthenticationManager().authenticate(authenticationToken);
        } catch (IOException e) {
            log.error("RequestBody 를 읽는 데 실패하였습니다.", e);
            throw new AuthenticationServiceException("RequestBody 를 읽는 데 실패하였습니다.");
        }
    }

    @Override
    protected void successfulAuthentication (HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException {
        String email = authResult.getName();
        CustomUserDetails userDetails = (CustomUserDetails) authResult.getPrincipal();
        MemberDto memberDto = userDetails.getMemberDto();

        String accessToken = jwtUtil.generateAccessToken(memberDto);
        String refreshToken = jwtUtil.generateRefreshToken(email);

        jwtUtil.addJwtToCookie(accessToken, response, "accessToken");
        jwtUtil.addJwtToCookie(refreshToken, response, "refreshToken");

        response.setStatus(HttpServletResponse.SC_OK);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"message\": \"로그인 성공\"}");
    }

    @Override
    protected void unsuccessfulAuthentication (HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        response.getWriter().write("{\"message\": \"로그인 실패\"}");
    }
}
