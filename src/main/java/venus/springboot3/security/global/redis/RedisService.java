package venus.springboot3.security.global.redis;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RedisService {

    private final RedisTemplate<String, Object> redisTemplate;

    public void saveRefreshToken (String email, String refreshToken) {
        redisTemplate.opsForValue().set(email, refreshToken, 7, TimeUnit.DAYS); // RefreshToken 만료 시간과 동일하게 설정
    }

    public String getRefreshToken (String email) {
        return (String) redisTemplate.opsForValue().get(email);
    }

    public void deleteRefreshToken (String email) {
        redisTemplate.delete(email);
    }
}
