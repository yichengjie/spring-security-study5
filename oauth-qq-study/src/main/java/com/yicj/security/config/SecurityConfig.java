package com.yicj.security.config;

import com.yicj.security.common.CompositeOAuth2UserService;
import com.yicj.security.common.CompositeOauth2AccessTokenResponseClient;
import com.yicj.security.qq.QQOAuth2UserService;
import com.yicj.security.qq.QQOauth2AccessTokenResponseClient;
import com.yicj.security.qq.QQUserInfo;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.user.OAuth2User;

// 从Spring Security5.0开始，HttpSecurity中提供了用于配置OAuth客户端的策略OAuth2Login()方法
// 关于重定向端点redirectionEndpoint的配置是可选的，需要注意的是，当多个OAuth服务提供商并存时，
// 一定要保证baseUri,redirect-uri-template和OAuth注册的重定向地址三者互相匹配
@EnableWebSecurity(debug = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    public static final String QQRegistrationId = "qq" ;
    public static final String WeChatRegistrationId = "wechat" ;
    public static final String loginPagePath = "/login/oauth2" ;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers(loginPagePath).permitAll()
                .anyRequest()
                .authenticated() ;

        http.oauth2Login()
                // 使用CompositeOauth2AccessTokenResponseClient
                .tokenEndpoint().accessTokenResponseClient(this.accessTokenResponseClient())
                .and()
                .userInfoEndpoint().customUserType(QQUserInfo.class, QQRegistrationId)
                // 使用CompositeOAuth2UserService
                .userService(this.oauth2UserService())
                // 可选，要保证与redirect-uri-template匹配
                .and()
                .redirectionEndpoint().baseUri("/register/social/**");

        // 自定义登录页面
        http.oauth2Login().loginPage(loginPagePath) ;
    }

    private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient() {
        CompositeOauth2AccessTokenResponseClient client = new CompositeOauth2AccessTokenResponseClient() ;
        //加入QQ自定义QQOauth2AccessTokenResponseClient
        client.getClients().put(QQRegistrationId, new QQOauth2AccessTokenResponseClient()) ;
        return client ;
    }

    private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService() {
        CompositeOAuth2UserService service = new CompositeOAuth2UserService() ;
        // 加入QQ自定义QQOAuth2UserService
        service.getUserServices().put(QQRegistrationId, new QQOAuth2UserService()) ;
        return service ;
    }
}
