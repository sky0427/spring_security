package venus.springboot3.security.global.custom;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import venus.springboot3.security.domain.member.entities.Member;
import venus.springboot3.security.domain.member.enums.MemberRole;
import venus.springboot3.security.domain.member.enums.Provider;
import venus.springboot3.security.domain.member.interfaces.OAuth2UserInfo;
import venus.springboot3.security.domain.member.repository.MemberRepository;

import java.util.Collections;
import java.util.List;
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
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(provider, oAuth2User.getAttributes()); // Factory Pattern 적용

        Optional<Member> memberOptional = memberRepository.findMemberByEmail(oAuth2UserInfo.getEmail());

        Member member = memberOptional.map(existingMember -> {
                    // 기존 member 가 있다면, update 로직을 실행합니다.
                    return updateMember(existingMember, oAuth2UserInfo);
                })
                .orElseGet(() -> createMember(oAuth2UserInfo, provider));

        List<GrantedAuthority> authorities = Collections.singletonList(new SimpleGrantedAuthority(member.getRole().toString()));

        return new CustomOAuth2User(oAuth2User, member, authorities);
    }

    @Transactional
    protected Member createMember (OAuth2UserInfo oAuth2UserInfo, String provider) {
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

    @Transactional
    protected Member updateMember(Member existingMember, OAuth2UserInfo oAuth2UserInfo) {
        // OAuth2 정보와 일치하도록 기존 회원 정보 업데이트
        existingMember.setNickname(oAuth2UserInfo.getName());
        // 필요한 다른 정보들도 업데이트

        try {
            return memberRepository.save(existingMember);
        } catch (Exception e) {
            String errorMessage = String.format("OAuth2 Provider(%s) : 회원 정보 업데이트에 실패했습니다: %s", existingMember.getProvider(), e.getMessage());
            log.error(errorMessage, e);
            throw new OAuth2AuthenticationException(errorMessage);
        }
    }
}
