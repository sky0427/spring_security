package venus.springboot3.security.global.custom;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;
import venus.springboot3.security.domain.member.dto.MemberDto;
import venus.springboot3.security.domain.member.entities.Member;

import java.util.Collection;
import java.util.Map;

@Getter
public class CustomOAuth2User implements OAuth2User {

    private final OAuth2User oAuth2User;
    private final MemberDto memberDto;

    public CustomOAuth2User (OAuth2User oAuth2User, Member member) {
        this.oAuth2User = oAuth2User;
        this.memberDto = new MemberDto(
                member.getEmail(),
                member.getNickname(),
                member.getProfileUrl(),
                member.getRole().name()
        );
    }

    @Override
    public Map<String, Object> getAttributes() {
        return oAuth2User.getAttributes();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return oAuth2User.getAuthorities();
    }

    @Override
    public String getName() {
        return oAuth2User.getName();
    }
}
