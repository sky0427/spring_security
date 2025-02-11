package venus.springboot3.security.global.custom;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import venus.springboot3.security.domain.member.entities.Member;

import java.util.Collection;
import java.util.List;
import java.util.Map;

@Getter
public class CustomOAuth2User implements OAuth2User, UserDetails {

    private final OAuth2User oAuth2User;
    private final Member member;
    private final Collection<? extends GrantedAuthority> authorities;

    public CustomOAuth2User (OAuth2User oAuth2User, Member member, Collection<? extends GrantedAuthority> authorities) {
        this.oAuth2User = oAuth2User;
        this.member = member;
        this.authorities = List.of(new SimpleGrantedAuthority("ROLE_" + member.getRole().name()));    // 권한 정보 설정
    }

    @Override
    public Map<String, Object> getAttributes() {
        return oAuth2User.getAttributes();
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getName() {
        return oAuth2User.getName();
    }

    @Override
    public String getPassword() {
        return null;    // 소셜 로그인은 비밀번호가 없으므로 null 반환
    }

    @Override
    public String getUsername() {
        return member.getEmail();   // 이메일을 username으로 사용
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;    // 계정 만료 여부 (항상 true)
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;    // 계정 잠금 여부 (항상 true)
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;    // 비밀번호 만료 여부 (항상 true)
    }

    @Override
    public boolean isEnabled() {
        return true;    // 계정 활성화 여부 (항상 true)
    }
}
