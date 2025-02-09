package venus.springboot3.security.global.custom;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import venus.springboot3.security.domain.member.entities.KakaoUserInfo;
import venus.springboot3.security.domain.member.entities.Member;
import venus.springboot3.security.domain.member.entities.NaverUserInfo;
import venus.springboot3.security.domain.member.enums.MemberRole;
import venus.springboot3.security.domain.member.enums.Provider;
import venus.springboot3.security.domain.member.interfaces.OAuth2UserInfo;
import venus.springboot3.security.domain.member.repository.MemberRepository;

import java.util.Map;
import java.util.Optional;

@Slf4j(topic = "CustomOAuth2UserService")
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final MemberRepository memberRepository;

    @Override
    public OAuth2User loadUser (OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        log.info("OAuth2User Attributes: " + oAuth2User.getAttributes());
        return processOAuth2User(userRequest, oAuth2User);
    }

    private OAuth2User processOAuth2User (OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        String provider = userRequest.getClientRegistration().getRegistrationId();
        OAuth2UserInfo oAuth2UserInfo = null;

        if (provider.equals("kakao")) {
            oAuth2UserInfo = new KakaoUserInfo(oAuth2User.getAttributes());
        } else if (provider.equals("naver")) {
            oAuth2UserInfo = new NaverUserInfo((Map) oAuth2User.getAttributes().get("response"));
        } else {
            String errorMessage = String.format("지원하지 않는 OAuth2 Provider 입니다: %s", provider);
            log.info(errorMessage);
            throw new OAuth2AuthenticationException(errorMessage);
        }

        Optional<Member> memberOptional = memberRepository.findMemberByEmail(oAuth2UserInfo.getEmail());

        Member member;

        if (memberOptional.isPresent()) {
            member = memberOptional.get();
        } else {
            member = createMember(oAuth2UserInfo, provider);
        }

        return new CustomOAuth2User(oAuth2User, member);
    }

    private Member createMember (OAuth2UserInfo oAuth2UserInfo, String provider) {
        Member member = Member.builder()
                .email(oAuth2UserInfo.getEmail())
                .nickname(oAuth2UserInfo.getName())
                .provider(Provider.valueOf(provider.toUpperCase()))
                .providerId(oAuth2UserInfo.getId())
                .role(MemberRole.USER)
                .build();
        try {
            return memberRepository.save(member);
        } catch (Exception e) {
            String errorMessage = String.format("회원 저장에 실패했습니다: %s", e.getMessage());
            log.error(errorMessage);
            throw new OAuth2AuthenticationException(errorMessage);
        }
    }
}
