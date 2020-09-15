package com.yicj.security.wechat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yicj.security.common.JacksonFromTextHtmlHttpMessageConverter;
import com.yicj.security.qq.QQUserInfo;
import org.springframework.http.MediaType;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.client.RestTemplate;
import org.thymeleaf.util.StringUtils;

import java.nio.charset.Charset;

public class WeChatOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    private RestTemplate restTemplate ;
    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        String accessToken = userRequest.getAccessToken().getTokenValue() ;
        String openId = (String) userRequest.getAdditionalParameters().get("openId") ;
        //https://api.weixin.qq.com/sns/userinfo?access_token=ACCESS_TOKEN&openid=OPENID
        String getUserInfoUrl = userRequest.getClientRegistration().getProviderDetails()
                .getUserInfoEndpoint().getUri() +"?access_token={accessToken}&openid={openId}" ;
        WeChatUserInfo userInfo = getRestTemplate().getForObject(
                getUserInfoUrl, WeChatUserInfo.class, accessToken, openId) ;
        return userInfo;
    }

    private RestTemplate getRestTemplate(){
        if (restTemplate == null){
            restTemplate = new RestTemplate() ;
            // 通过jackson json processing library 直接将返回值绑定到对象
            //restTemplate.getMessageConverters().add(new StringHttpMessageConverter(Charset.forName("UTF-8"))) ;
            restTemplate.getMessageConverters().add(new JacksonFromTextHtmlHttpMessageConverter(MediaType.TEXT_PLAIN)) ;
        }
        return restTemplate ;
    }
}
