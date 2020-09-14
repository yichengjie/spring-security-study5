package com.yicj.security.wechat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import com.yicj.security.common.TextHtmlHttpMessageConverter;
import org.apache.commons.collections.MapUtils;
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

public class WeChatOauth2AccessTokenResponseClient implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {

    private RestTemplate restTemplate ;

    @Override
    public OAuth2AccessTokenResponse getTokenResponse(OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
        ClientRegistration clientRegistration = authorizationGrantRequest.getClientRegistration() ;
        OAuth2AuthorizationExchange authorizationExchange = authorizationGrantRequest.getAuthorizationExchange();
        OAuth2AuthorizationResponse authorizationResponse = authorizationExchange.getAuthorizationResponse();
        // 根据api文档获取请求access_token参数
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>() ;
        params.set("appid", clientRegistration.getClientId());
        params.set("secret", clientRegistration.getClientSecret());
        params.set("code", authorizationResponse.getCode());
        params.set("redirect_uri", authorizationResponse.getRedirectUri());
        params.set("grant_type", "authorization_code");
        String tmpTokenResponse = getRestTemplate().postForObject(
                clientRegistration.getProviderDetails().getTokenUri(), params, String.class) ;
        Map<String, Object> result = null;
        try {
            result = new ObjectMapper().readValue(tmpTokenResponse, Map.class);
        } catch (Exception e) {
            e.printStackTrace();
        }
        //返回错误码时直接返回空
        if(StringUtils.isNotBlank(MapUtils.getString(result, "errcode"))){
            String errcode = MapUtils.getString(result, "errcode");
            String errmsg = MapUtils.getString(result, "errmsg");
            throw new RuntimeException("获取access token失败, errcode:"+errcode+", errmsg:"+errmsg);
        }

        OAuth2AccessToken.TokenType accessTokenType = OAuth2AccessToken.TokenType.BEARER ;
        Set<String> scopes = new LinkedHashSet<>(authorizationExchange.getAuthorizationRequest().getScopes()) ;
        Map<String,Object> additionalParameters = new LinkedHashMap<>() ;
        additionalParameters.put("openId", MapUtils.getString(result,"openid"));

        return OAuth2AccessTokenResponse
                .withToken(MapUtils.getString(result, "access_token"))
                .tokenType(accessTokenType)
                .expiresIn(MapUtils.getLong(result, "expires_in"))
                .scopes(scopes)
                .refreshToken(MapUtils.getString(result, "refresh_token"))
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
