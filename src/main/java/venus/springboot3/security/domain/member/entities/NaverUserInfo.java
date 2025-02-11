package venus.springboot3.security.domain.member.entities;

import venus.springboot3.security.domain.member.interfaces.OAuth2UserInfo;

import java.util.Map;
import java.util.Objects;

public class NaverUserInfo implements OAuth2UserInfo {

    private Map<String, Object> attributes;

    public NaverUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
    }

    @Override
    public String getId() {
        return Objects.toString(attributes.get("id"), "");
    }

    @Override
    public String getName() {
        return Objects.toString(attributes.get("name"), "");
    }

    @Override
    public String getEmail() {
        return Objects.toString(attributes.get("email"), "");
    }
}
