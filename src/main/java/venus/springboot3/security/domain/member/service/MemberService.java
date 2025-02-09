package venus.springboot3.security.domain.member.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import venus.springboot3.security.domain.member.dto.SignupRequestDto;
import venus.springboot3.security.domain.member.entities.Member;
import venus.springboot3.security.domain.member.enums.MemberRole;
import venus.springboot3.security.domain.member.enums.Provider;
import venus.springboot3.security.domain.member.repository.MemberRepository;

@Slf4j(topic = "MemberService")
@Service
@RequiredArgsConstructor
public class MemberService {

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    @Transactional
    public void signup (SignupRequestDto requestDto) {
        if (memberRepository.existsByEmail(requestDto.getEmail())) {
            throw new IllegalArgumentException("이미 가입된 이메일입니다.");
        }

        Member member = Member.builder()
                .email(requestDto.getEmail())
                .password(passwordEncoder.encode(requestDto.getPassword()))
                .nickname(requestDto.getNickname())
                .role(MemberRole.USER)
                .provider(Provider.LOCAL)
                .build();

        memberRepository.save(member);
    }

    public Member findByEmail (String email) {
        return memberRepository.findMemberByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 이메일입니다."));
    }
}
