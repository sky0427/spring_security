package venus.springboot3.security.domain.member.entities;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.SuperBuilder;
import venus.springboot3.security.domain.member.enums.MemberRole;
import venus.springboot3.security.domain.member.enums.Provider;
import venus.springboot3.security.global.jpa.BaseEntity;

@Entity
@Getter
@Setter
@Table(name = "members")
@AllArgsConstructor
@NoArgsConstructor
@SuperBuilder
@ToString(callSuper = true)
public class Member extends BaseEntity {

    @Column(unique = true, nullable = false)
    private String email; //이게 id 역할
    @Column(nullable = false)
    private String password;
    @Column(unique = true, nullable = false)
    private String nickname;
    private String profileUrl;

    @Enumerated(value = EnumType.STRING)
    @Column(nullable = false)
    private MemberRole role;

    @Enumerated(value = EnumType.STRING)
    @Column(nullable = false)
    private Provider provider; // 로그인 타입
    private String providerId; // 소셜로그인 시 ID                 /* 사용자 권한 */
}
