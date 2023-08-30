package com.security.jwt.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.security.jwt.auth.PrincipalDetails;
import com.security.jwt.model.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }


    //로그인 요청 시 실행된다.
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter: 로그인 시도중");

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            User user = objectMapper.readValue(request.getInputStream(), User.class);
            System.out.println("User: " + user);

            //token 생성
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            //PricipalDetailsService의 loadUserByUsername() 함수가 실행된다.
            Authentication authentication = getAuthenticationManager().authenticate(authenticationToken);

            // authentication 객체가 session 영역에 저장된다. (인증 완료시에만)
            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println("principalDetails - username: " + principalDetails.getUser().getUsername());

            //로그인 완료
            //권한 처리를 하기 위해 세션에 authentication 객체를 저장하여 return 한다.
            return authentication;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    //attemptAuthentication 메소드가 실행 후 인증이 정상적으로 완료되면 successfulAuthentication 메소드가 실행된다.
    //JWT 토큰을 만들어서 이 토큰을 사용자에게 response 하면 된다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {

        System.out.println("successfulAuthentication is called");

        super.successfulAuthentication(request, response, chain, authResult);
    }
}
