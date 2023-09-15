package org.example.authorization.uaa.wapper;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;

public class TokenHeaderWrapper extends HttpServletRequestWrapper {

    private final String token;

    public TokenHeaderWrapper(HttpServletRequest request, String token) {
        super(request);
        this.token = token;
    }

    @Override
    public String getParameter(String name) {
        if ("token".equals(name)) {
            return token;
        }
        return super.getParameter(name);
    }


}
