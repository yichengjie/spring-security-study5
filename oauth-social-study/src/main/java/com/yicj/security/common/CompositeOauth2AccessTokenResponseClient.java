package com.yicj.security.common;

import org.springframework.security.oauth2.client.endpoint.NimbusAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;

import java.util.HashMap;
import java.util.Map;

// 多个OAuth服务提供商并存
// 前面我们通过自定义实现QQOauth2AccessTokenResponseClient和QQOAuth2UserService来支持QQ登录
// 但如果直接使用他们分别替代默认NimbusAuthorizationCodeTokenResponseClient和DefaultOAuth2UserService,
// 将会导致GitHub等标准OAuth服务无法正常使用，为了让多个OAuth服务可以并存，建议使用组合模式
// 根据registrationId选择相应的OAuth2AccessTokenResponseClient
public class CompositeOauth2AccessTokenResponseClient  implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {
    private Map<String,OAuth2AccessTokenResponseClient> clients ;
    private static final String DEFAULT_CLIENT_KEY = "default_key" ;

    public CompositeOauth2AccessTokenResponseClient(){
        this.clients = new HashMap<>() ;
        // spring-security-oauth2-client默认的Oauth2AccessTokenResponseClient
        // 实现类是NimbusAuthorizationCodeTokenResponseClient，将其预置到组合类CompositeOauth2AccessTokenResponseClient中，
        // 使其默认支持Google，Okta，GitHub和Facebook
        this.clients.put(DEFAULT_CLIENT_KEY, new NimbusAuthorizationCodeTokenResponseClient()) ;
    }

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
        ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration();
        OAuth2AccessTokenResponseClient client = clients.get(clientRegistration.getRegistrationId());
        if (client == null){
            client = clients.get(DEFAULT_CLIENT_KEY) ;
        }
        return client.getTokenResponse(authorizationGrantRequest);
    }

    public Map<String, OAuth2AccessTokenResponseClient> getClients() {
        return clients;
    }
}
