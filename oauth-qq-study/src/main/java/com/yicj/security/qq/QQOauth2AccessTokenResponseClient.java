package com.yicj.security.qq;

import com.yicj.security.common.TextHtmlHttpMessageConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

// 自定义OAuth2AccessTokenResponseClient实现了以code交换access_token的具体逻辑。
// 默认NimbusAuthorizationCodeTokenResponseClient可以实现标准的OAuth交换access_token的具体逻辑，
// 但QQ提供的方式并不标准，所以需要自定义实现OAuth2AccessTokenResponseClient
public class QQOauth2AccessTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {
    private RestTemplate restTemplate ;

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
        ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration() ;
        OAuth2AuthorizationExchange authorizationExchange = authorizationGrantRequest.getAuthorizationExchange();
        OAuth2AuthorizationResponse authorizationResponse = authorizationExchange.getAuthorizationResponse();
        // 根据api文档获取请求access_token参数
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>() ;
        params.set("client_id", clientRegistration.getClientId());
        params.set("client_secret", clientRegistration.getClientSecret());
        params.set("code", authorizationResponse.getCode());
        params.set("redirect_uri", authorizationResponse.getRedirectUri());
        params.set("grant_type", "authorization_code");
        String tmpTokenResponse = getRestTemplate().postForObject(
                clientRegistration.getProviderDetails().getTokenUri(), params, String.class) ;

        // 从API文档中可以获得解析accessToken的方式
        String[] items = tmpTokenResponse.split("&");
        // http://wiki.connect.qq.com使用authorization_code获取access_token
        // access_token=FE04*******CCE2&expires_in776000&refresh_token=88E4******BE14
        String accessToken = items[0].substring(items[0].lastIndexOf("=") +1) ;
        Long expiresIn = new Long(items[1].substring(items[1].lastIndexOf("=") + 1)) ;
        Set<String> scopes = new LinkedHashSet<>(authorizationExchange.getAuthorizationRequest().getScopes()) ;
        Map<String,Object> additionalParameters = new LinkedHashMap<>() ;
        OAuth2AccessToken.TokenType accessTokenType = OAuth2AccessToken.TokenType.BEARER ;

        return OAuth2AccessTokenResponse
                .withToken(accessToken)
                .tokenType(accessTokenType)
                .expiresIn(expiresIn)
                .scopes(scopes)
                .additionalParameters(additionalParameters)
                .build();
    }


    private RestTemplate getRestTemplate(){
        if (restTemplate == null){
            restTemplate = new RestTemplate() ;
            restTemplate.getMessageConverters().add(new TextHtmlHttpMessageConverter()) ;
        }
        return restTemplate ;
    }
}
