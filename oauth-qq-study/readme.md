+ 添加项目依赖
``` text
   <dependency>
       <groupId>org.springframework.boot</groupId>
       <artifactId>spring-boot-starter-web</artifactId>
   </dependency>

   <dependency>
       <groupId>org.springframework.boot</groupId>
       <artifactId>spring-boot-starter-security</artifactId>
   </dependency>

   <!--spring security 为 oauth提供支持的专用依赖包 start-->
   <dependency>
       <groupId>org.springframework.security</groupId>
       <artifactId>spring-security-config</artifactId>
   </dependency>

   <dependency>
       <groupId>org.springframework.security</groupId>
       <artifactId>spring-security-oauth2-client</artifactId>
   </dependency>

   <dependency>
       <groupId>org.springframework.security</groupId>
       <artifactId>spring-security-oauth2-jose</artifactId>
   </dependency>
   <!--spring security 为 oauth提供支持的专用依赖包 end-->     
```
+ 自定义QQUserInfo实现OAuth2User接口
```text
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
```
+ 添加RestTemplate解析模板
```text
public class JacksonFromTextHtmlHttpMessageConverter extends MappingJackson2HttpMessageConverter {
    // 添加对text/html的支持
    public JacksonFromTextHtmlHttpMessageConverter(){
        List<MediaType> mediaTypes = new ArrayList() ;
        mediaTypes.add(MediaType.TEXT_HTML) ;
        setSupportedMediaTypes(mediaTypes);
    }
}

public class TextHtmlHttpMessageConverter extends AbstractHttpMessageConverter<String> {
    public TextHtmlHttpMessageConverter(){
        super(Charset.forName("UTF-8"), new MediaType[]{MediaType.TEXT_HTML});
    }
    @Override
    protected boolean supports(Class clazz) {
        return String.class == clazz;
    }

    @Override
    protected String readInternal(Class clazz, HttpInputMessage inputMessage) throws IOException, HttpMessageNotReadableException {
        Charset charset = this.getContentTypeCharset(inputMessage.getHeaders().getContentType()) ;
        return StreamUtils.copyToString(inputMessage.getBody(), charset);
    }
    @Override
    protected void writeInternal(String o, HttpOutputMessage outputMessage) throws IOException, HttpMessageNotWritableException {
    }
    private Charset getContentTypeCharset(MediaType contentType){
        return contentType != null && contentType.getCharset() !=null
                ? contentType.getCharset() : this.getDefaultCharset() ;
    }
}
```
+ 自定义OAuth2AccessTokenResponseClient实现了以code交换access_token的具体逻辑
```text
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
```
+ 实现OAuth2UserService接口获取用户信息
```text
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
```
+ 多个OAuth服务提供商并存
```text
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
```
+ 配置Spring Security
```text
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
```
+ 工程配置文件
```text
server:
  port: 8080
  
logging:
  level:
    root: INFO
    org.springframework.web: INFO
    org.springframework.security: DEBUG
    org.springframework.boot.autoconfigure: DEBUG

spring:
  security:
    oauth2:
      client:
        registration:
          github:
            client-id: {custom}
            client-secret: {custom}
            redirect-uri-template: "{baseUrl}/register/social/{registrationId}"
          qq:
            client-id: {custom appId}
            client-secret: {custom appKey}
            provider: qq
            client-name: QQ登录
            authorization-grant-type: authorization_code
            client-authentication-method: post
            scope: get_user_info,list_album,upload_pic,do_like
            redirect-uri-template: "{baseUrl}/register/social/{registrationId}"
        provider:
          qq:
            authorization-uri: https://graph.qq.com/oauth2.0/authorize
            token-uri: https://graph.qq.com/oauth2.0/token
            # 配置为QQ获取OpenId的URL
            user-info-uri: https://graph.qq.com/oauth2.0/me
            user-name-attribute: "nickname"
```
+ 编写controller类
```text
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
```

