package com.yicj.security.qq;


import com.yicj.security.common.JacksonFromTextHtmlHttpMessageConverter;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.client.RestTemplate;

// Auth2UserService 负责请求用户信息(OAuth2User)。
// 标准的OAuth可以直接携带access_token请求用户信息,但是QQ需要获取到OpenId才能使用
public class QQOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {
    // 获取用户信息的API
    private static final String QQ_URL_GET_USER_INFO = "https://graph.qq.com/user/get_user_info?oauth_consumer_key={appId}&openid={openId}&access_token={access_token}";

    private RestTemplate restTemplate ;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 第一步：获取获取openId接口响应
        String accessToken = userRequest.getAccessToken().getTokenValue() ;
        String openIdUrl = userRequest.getClientRegistration().getProviderDetails()
                .getUserInfoEndpoint().getUri() +"?access_token={accessToken}" ;
        String result = getRestTemplate().getForObject(openIdUrl, String.class, accessToken) ;
        // 提取openId
        String openId = result.substring(result.lastIndexOf(":\"") + 2, result.indexOf("\"}")) ;
        // 第二步：获取用户信息
        String appId = userRequest.getClientRegistration().getClientId() ;

        QQUserInfo qqUserInfo = getRestTemplate().getForObject(
                QQ_URL_GET_USER_INFO, QQUserInfo.class, appId, openId, accessToken) ;
        // 为用户信息类补充openId
        if (qqUserInfo != null){
            qqUserInfo.setOpenId(openId);
        }
        return qqUserInfo;
    }

    private RestTemplate getRestTemplate(){
        if (restTemplate == null){
            restTemplate = new RestTemplate() ;
            // 通过jackson json processing library 直接将返回值绑定到对象
            restTemplate.getMessageConverters().add(new JacksonFromTextHtmlHttpMessageConverter()) ;
        }
        return restTemplate ;
    }
}
