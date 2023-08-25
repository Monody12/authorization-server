package org.example.authorization.uaa.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

@Configuration
@EnableAuthorizationServer // 开启授权服务
public class AuthorizationServer extends AuthorizationServerConfigurerAdapter {
    /**
     * 客户端信息服务
     */
    @Autowired
    private ClientDetailsService clientDetailsService;
    /**
     * 令牌存储策略
     */
    @Autowired
    private TokenStore tokenStore;
    @Autowired
    private AuthorizationCodeServices authorizationCodeServices;
    @Autowired
    private AuthenticationManager authenticationManager;

    @Bean
    public AuthorizationCodeServices authorizationCodeServices() {
        return new InMemoryAuthorizationCodeServices();
    }

    /**
     * 令牌访问端点安全策略
     * @param security
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.tokenKeyAccess("permitAll()") // oauth/token_key是公开
                .checkTokenAccess("permitAll()") // oauth/check_token公开
                .allowFormAuthenticationForClients(); // 表单认证（申请令牌）
    }

    /**
     * 配置客户端详情信息
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        //  使用内存存储客户端信息
        clients.inMemory()
                .withClient("c1") // 客户端id
                .secret(new BCryptPasswordEncoder().encode("secret")) // 客户端秘钥
                .resourceIds("res1") // 资源列表
                .authorizedGrantTypes("authorization_code", "password", "client_credentials", "implicit", "refresh_token") // 该客户端允许的授权类型
                .scopes("all") // 允许的授权范围
                .autoApprove(false) // false 跳转到授权页面
                .redirectUris("https://www.baidu.com"); // 回调地址
    }

    /**
     * 令牌访问端点
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints.authenticationManager(authenticationManager) // 密码模式需要
                .authorizationCodeServices(authorizationCodeServices) // 授权码模式需要
                .tokenServices(tokenServices()) // 令牌管理服务
                .allowedTokenEndpointRequestMethods(HttpMethod.POST); // 允许post提交
    }



    @Bean
    public AuthorizationServerTokenServices tokenServices() {
        DefaultTokenServices services = new DefaultTokenServices();
        services.setClientDetailsService(clientDetailsService); // 客户端信息服务
        services.setSupportRefreshToken(true); // 支持刷新令牌
        services.setTokenStore(tokenStore); // 令牌存储策略
        services.setAccessTokenValiditySeconds(7200); // 令牌默认有效期2小时
        services.setRefreshTokenValiditySeconds(259200); // 刷新令牌默认有效期3天
        return services;
    }
}
