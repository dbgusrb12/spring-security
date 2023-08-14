package com.hg.security;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests()    // 인가 방식 설정
            .anyRequest().authenticated(); // 모든 request 는 인증이 되어야 한다.

        http
            .formLogin() // form login 인증 기능 설정
            .loginPage("/loginPage") // 사용자 정의 로그인 페이지 설정
            .defaultSuccessUrl("/") // 로그인 성공 후 이동 페이지
            .failureUrl("/login") // 로그인 실패 후 이동 페이지
            .usernameParameter("userId") // form username 파라미터명 설정 (default: username)
            .passwordParameter("passwd") // form password 파라미터명 설정 (default: password)
            .loginProcessingUrl("/login_proc") // login form action url
            .successHandler(new AuthenticationSuccessHandler() { // login 성공 후 핸들러
                @Override
                public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                    System.out.println("authentication : " + authentication.getName());
                    response.sendRedirect("/");
                }
            })
            .failureHandler(new AuthenticationFailureHandler() { // login 실패 후 핸들러
                @Override
                public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                    System.out.println("exception : " + exception.getMessage());
                    response.sendRedirect("/loginPage");
                }
            })
            .permitAll(); // form login 인증 페이지는 권한이 필요 하지 않도록 설정

        return http.build();
    }
}
