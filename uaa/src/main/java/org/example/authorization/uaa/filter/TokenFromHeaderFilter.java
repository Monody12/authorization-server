package org.example.authorization.uaa.filter;

import org.example.authorization.uaa.wapper.ParameterRequestUtils;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class TokenFromHeaderFilter extends OncePerRequestFilter {

    private final DefaultTokenServices tokenServices;

    public TokenFromHeaderFilter(DefaultTokenServices tokenServices) {
        this.tokenServices = tokenServices;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = extractTokenFromHeader(request);
        ParameterRequestUtils wrapper = null;
        if (token != null) {
            // 替换请求中的token参数为从请求头中获取的token
            wrapper = new ParameterRequestUtils(request);
            wrapper.addParameter("token",token);
        }

        filterChain.doFilter(wrapper == null ? request : wrapper, response);
    }

    private String extractTokenFromHeader(HttpServletRequest request) {
        // 从请求头中提取token，这里使用Authorization头
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7); // 去掉"Bearer "前缀，获取token
        }
        return null;
    }
}