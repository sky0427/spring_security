package venus.springboot3.security.global.custom;

import venus.springboot3.security.domain.member.entities.KakaoUserInfo;
import venus.springboot3.security.domain.member.entities.NaverUserInfo;
import venus.springboot3.security.domain.member.interfaces.OAuth2UserInfo;

import java.util.Map;

public class OAuth2UserInfoFactory {
    public static OAuth2UserInfo getOAuth2UserInfo(String provider, Map<String, Object> attributes) {
        if (provider.equals("kakao")) {
            return new KakaoUserInfo(attributes);
        } else if (provider.equals("naver")) {
            return new NaverUserInfo(attributes);
        } else {
            throw new IllegalArgumentException("Invalid OAuth2 Provider: " + provider);
        }
    }
}
