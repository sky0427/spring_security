package venus.springboot3.security.domain.member.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.*;
import venus.springboot3.security.domain.member.dto.LoginRequestDto;
import venus.springboot3.security.domain.member.dto.MemberDto;
import venus.springboot3.security.domain.member.dto.SignupRequestDto;
import venus.springboot3.security.domain.member.entities.Member;
import venus.springboot3.security.domain.member.service.MemberService;
import venus.springboot3.security.global.redis.RedisService;
import venus.springboot3.security.global.util.JwtUtil;

@Slf4j(topic = "MemberController")
@RestController
@RequiredArgsConstructor
@RequestMapping("/api/member")
public class MemberController {

    private final MemberService memberService;
    private final BCryptPasswordEncoder passwordEncoder; // 로그인 시 비밀번호 검증에 필요
    private final JwtUtil jwtUtil;
    private final RedisService redisService;

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody SignupRequestDto requestDto) {
        try {
            memberService.signup(requestDto);
            return new ResponseEntity<>("회원가입 성공", HttpStatus.OK);
        } catch (IllegalArgumentException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<String> login (@RequestBody LoginRequestDto requestDto, HttpServletResponse response) {
        try {
            Member member = memberService.findByEmail(requestDto.getEmail());

            if (!passwordEncoder.matches(requestDto.getPassword(), member.getPassword())) {
                return new ResponseEntity<>("비밀번호가 일치하지 않습니다.", HttpStatus.UNAUTHORIZED);
            }

            String accessToken = jwtUtil.generateAccessToken(member.getEmail(), member.getRole().name());
            String refreshToken = jwtUtil.generateRefreshToken(member.getEmail());

            jwtUtil.addJwtToCookie(accessToken, response, "accessToken");
            jwtUtil.addJwtToCookie(refreshToken, response, "refreshToken");

            redisService.saveRefreshToken(member.getEmail(), refreshToken);

            return new ResponseEntity<>("로그인 성공", HttpStatus.OK);
        } catch (IllegalArgumentException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.UNAUTHORIZED);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<String> logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        // 1. Spring Security Context Logout 처리
        if (authentication != null) {
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }

        // 2. JWT 쿠키 삭제
        jwtUtil.deleteJwtFromCookie(response, "accessToken");
        jwtUtil.deleteJwtFromCookie(response, "refreshToken");

        // 3. RefreshToken 삭제
        String refreshToken = jwtUtil.resolveToken(request);

        if (refreshToken != null) {
            String email = jwtUtil.getMemberEmailFromToken(refreshToken);
            redisService.deleteRefreshToken(email);
        }

        return new ResponseEntity<>("로그아웃 성공", HttpStatus.OK);
    }

    @GetMapping("/refresh")
    public ResponseEntity<String> refresh(HttpServletRequest request, HttpServletResponse response) {
        String refreshToken = jwtUtil.resolveToken(request);

        if (refreshToken != null) {
            if (jwtUtil.validateToken(refreshToken)) {
                String email = jwtUtil.getMemberEmailFromToken(refreshToken);
                String savedRefreshToken = redisService.getRefreshToken(email);

                if (savedRefreshToken != null && savedRefreshToken.equals(refreshToken)) {
                    Member member = memberService.findByEmail(email);

                    String newAccessToken = jwtUtil.generateAccessToken(member.getEmail(), member.getRole().name());
                    jwtUtil.addJwtToCookie(newAccessToken, response, "accessToken");
                    return new ResponseEntity<>("AccessToken 갱싱 성공", HttpStatus.OK);
                } else {
                    return new ResponseEntity<>("RefreshToken 이 일치하지 않습니다.", HttpStatus.BAD_REQUEST);
                }
            } else {
                return new ResponseEntity<>("유효하지 않은 RefreshToken 입니다.", HttpStatus.BAD_REQUEST);
            }
        } else {
            return new ResponseEntity<>("RefreshToken 이 존재하지 않습니다.", HttpStatus.BAD_REQUEST);
        }
    }
}
