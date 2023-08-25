package org.example.authorization.uaa.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

@Configuration
public class TokenConfig {
    @Bean
    public TokenStore tokenStore() {
        // 使用内存存储令牌
        return new InMemoryTokenStore();
    }
}