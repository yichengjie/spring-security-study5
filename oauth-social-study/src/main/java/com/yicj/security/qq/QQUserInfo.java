package com.yicj.security.qq;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Data
public class QQUserInfo implements OAuth2User {
    // 统一赋予USER角色
    private List<GrantedAuthority> authorities =
            AuthorityUtils.createAuthorityList("ROLE_USER") ;
    private Map<String, Object> attributes ;
    private String nickname ;
    @JsonProperty("figureurl")
    private String figureUrl30 ;
    @JsonProperty("figureurl_1")
    private String figureUrl50 ;
    @JsonProperty("figureurl_2")
    private String figureUrl100 ;
    @JsonProperty("figureurl_qq_1")
    private String qqFigureUrl40 ;
    @JsonProperty("figureurl_qq_2")
    private String qqFigureUrl100 ;
    private String gender ;
    private String openId ;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public Map<String, Object> getAttributes() {
        if (this.attributes == null){
            attributes = new HashMap<>() ;
            attributes.put("nickname", this.getNickname()) ;
            attributes.put("figureUrl30", this.getFigureUrl30()) ;
            attributes.put("figureUrl50", this.getFigureUrl50()) ;
            attributes.put("figureUrl100", this.getFigureUrl100()) ;
            attributes.put("qqFigureUrl40", this.getQqFigureUrl40()) ;
            attributes.put("qqFigureUrl100", this.getQqFigureUrl100()) ;
            attributes.put("gender", this.getGender()) ;
            attributes.put("openId", this.getOpenId()) ;
        }
        return attributes;
    }

    @Override
    public String getName() {
        return nickname;
    }
}
