package com.security.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        System.out.println("필터3");

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        if (req.getMethod().equals("POST")) {
            System.out.println("POST 요청");
            String headerAuth = req.getHeader("Authorization");
            System.out.println("Authorization: " + headerAuth);

            //token이 abc일 때만 실행
            if (headerAuth.equals("abc")) {
                chain.doFilter(req, res);
            } else {
                res.getWriter().println("인증되지 않음.");
            }
        }
    }
}
