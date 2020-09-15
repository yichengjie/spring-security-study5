package com.yicj.security.wechat;

import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import javax.servlet.http.HttpServletRequest;

public class WeChatOAuth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
    private DefaultOAuth2AuthorizationRequestResolver requestResolver ;
    private String authorizationRequestBaseUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

    public WeChatOAuth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository,String authorizationRequestBaseUri){
        if (authorizationRequestBaseUri != null){
            this.authorizationRequestBaseUri = authorizationRequestBaseUri ;
        }
        requestResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, this.authorizationRequestBaseUri) ;
        //对builder中的数据进行修改
        requestResolver.setAuthorizationRequestCustomizer(builder -> {
            // 对build中的参数进行修改
            builder.parameters(stringObjectMap -> {
                Object clientId = stringObjectMap.get("client_id");
                stringObjectMap.put("appid", clientId) ;
            }) ;
        });
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
        return requestResolver.resolve(request);
    }

    @Override
    public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
        return requestResolver.resolve(request, clientRegistrationId);
    }
}
