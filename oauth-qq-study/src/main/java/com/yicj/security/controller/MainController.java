package com.yicj.security.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

// OAuth2AuthenticationToken可以获取当前用户信息，由Spring Security自动注入，
//OAuth2AuthorizedClientService对象可以用来获取当前已经认证成功的OAuth客户端信息
@Controller
public class MainController {
    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService ;

    @GetMapping("/")
    public String index(Model model, OAuth2AuthenticationToken authentication){
        OAuth2AuthorizedClient authorizedClient = this.getAuthorizedClient(authentication) ;
        model.addAttribute("userName", authentication.getName()) ;
        model.addAttribute("clientName", authorizedClient.getClientRegistration().getClientName()) ;
        return "index" ;
    }

    @GetMapping("/login/oauth2")
    public String login(){
        return "login" ;
    }

    private OAuth2AuthorizedClient getAuthorizedClient(OAuth2AuthenticationToken authentication) {
        return this.authorizedClientService.loadAuthorizedClient(
                authentication.getAuthorizedClientRegistrationId(), authentication.getName()) ;
    }
}
