package com.security.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class CorsConfig {

    /**
     * CorsCofig 중 @CrossOrigin 인증이 필요없을 때 Controller에 사용할 수 있다.
     * 인증이 필요할 때에는 반드시 Filter에 등록이 필요하다.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true); //서버가 응답할 때 json을 자바스크립트에서 처리할 수 있게 할지 설정한다.
        config.addAllowedOrigin("*"); //모든 IP에 응답 허용
        config.addAllowedHeader("*"); //모든 header에 응답 허용
        config.addAllowedMethod("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);

        return source;
    }
}
