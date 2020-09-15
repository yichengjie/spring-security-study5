package com.yicj.security.common;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.HashMap;
import java.util.Map;

public class CompositeOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private Map<String, OAuth2UserService> userServices ;
    private static final String DEFAULT_USERSERVICE_KEY = "default_key" ;

    public CompositeOAuth2UserService(){
        this.userServices = new HashMap<>() ;
        // DefaultOauth2UserService是默认处理OAuth获取用户逻辑的OAuthUserService实现类
        // 将其预置到组合类CompositeOAuth2UserService中，从而默认支持Google,Okta,Github,Facebook
        this.userServices.put(DEFAULT_USERSERVICE_KEY, new DefaultOAuth2UserService()) ;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        ClientRegistration clientRegistration = userRequest.getClientRegistration();
        OAuth2UserService service = userServices.get(clientRegistration.getRegistrationId());
        if (service == null){
            service = userServices.get(DEFAULT_USERSERVICE_KEY) ;
        }
        return service.loadUser(userRequest);
    }

    public Map<String, OAuth2UserService> getUserServices() {
        return userServices;
    }
}
