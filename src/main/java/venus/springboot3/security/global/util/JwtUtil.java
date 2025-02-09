package venus.springboot3.security.global.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import venus.springboot3.security.domain.member.dto.MemberDto;

import javax.crypto.SecretKey;
import java.util.Date;


@Slf4j
@Component
public class JwtUtil {

    public static final String AUTHORIZATION_KEY = "auth";
    public static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.access-token-expiration}")
    private Long ACCESS_TOKEN_EXPIRATION_TIME;

    @Value("${jwt.refresh-token-expiration}")
    private Long REFRESH_TOKEN_EXPIRATION_TIME;

    private final SecretKey key;

    // Bean 등록 시 SecretKey 초기화
    public JwtUtil (@Value("${jwt.secret}") String secretKey) {
        this.secretKey = secretKey;
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    public String getMemberEmailFromToken (String token) {
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
    }

    public boolean validateToken (String token) {
        try {
            Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (Exception e) {
            log.error("유효하지 않은 JWT Token: {}", e.getMessage());
            return false;
        }
    }

    public String generateAccessToken (MemberDto memberDto) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + ACCESS_TOKEN_EXPIRATION_TIME);

        return Jwts.builder()
                .subject(memberDto.getEmail())
                .claim(AUTHORIZATION_KEY, memberDto.getRole())
                .claim("nickname", memberDto.getNickname())
                .claim("profileUrl", memberDto.getProfileUrl())
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    public String generateRefreshToken (String email) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + REFRESH_TOKEN_EXPIRATION_TIME);

        return Jwts.builder()
                .subject(email)
                .issuedAt(now)
                .expiration(expiryDate)
                .signWith(key, Jwts.SIG.HS256)
                .compact();
    }

    public MemberDto getUserInfoFromToken (String token) {
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return new MemberDto(
                claims.getSubject(),                                // 이메일
                claims.get("nickname", String.class),           // 닉네임
                claims.get("profileUrl", String.class),         // 프로필 이미지
                claims.get(AUTHORIZATION_KEY, String.class)         // 권한
        );
    }

    public void addJwtToCookie (String token, HttpServletResponse response, String cookieName) {
        Cookie cookie = new Cookie(cookieName, token);
        cookie.setPath("/");
        // cookie.setHttpOnly(true); // Javascript 에서 접근 방지
        // cookie.setSecure(true); // HTTPS 환경에서만 전송
        response.addCookie(cookie);
    }

    public void deleteJwtFromCookie (HttpServletResponse response, String cookieName) {
        Cookie cookie = new Cookie(cookieName, null);
        cookie.setPath("/");
        // cookie.setHttpOnly(true);
        // cookie.setSecure(true);
        cookie.setMaxAge(0);
        response.addCookie(cookie);
    }

    public String getJwtFromHeader (HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (bearerToken != null && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public String resolveToken (HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals("refreshToken")) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
