package venus.springboot3.security.global.custom;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import venus.springboot3.security.domain.member.dto.MemberDto;
import venus.springboot3.security.domain.member.entities.Member;
import venus.springboot3.security.domain.member.repository.MemberRepository;

@Service
@RequiredArgsConstructor
// 인증에 필요한 사용자 정보를 UserDetails 객체로 로드하는 역할
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    @Override
    public UserDetails loadUserByUsername (String email) throws UsernameNotFoundException {
        Member member = memberRepository.findMemberByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("해당 사용자를 찾을 수 없습니다."));

        return new CustomUserDetails(member);
    }
}
