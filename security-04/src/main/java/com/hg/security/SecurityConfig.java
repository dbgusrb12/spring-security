package com.hg.security;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final UserDetailsService userDetailsService;

    public SecurityConfig(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests()
            .anyRequest().authenticated();

        http
            .formLogin() // form login 인증 기능 설정
            .defaultSuccessUrl("/") // 로그인 성공 후 이동 페이지
            .failureUrl("/login") // 로그인 실패 후 이동 페이지
            .usernameParameter("userId") // form username 파라미터명 설정 (default: username)
            .passwordParameter("passwd") // form password 파라미터명 설정 (default: password)
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
                    response.sendRedirect("/login");
                }
            })
            .permitAll(); // form login 인증 페이지는 권한이 필요 하지 않도록 설정

        http
            .logout() // logout 기능 설정
            .logoutUrl("/logout") // 로그아웃 처리 url (default: /logout)
            .logoutSuccessUrl("/login") // 로그아웃 성공 후 이동 페이지
            .addLogoutHandler(new LogoutHandler() { // 로그아웃 핸들러
                @Override
                public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                    HttpSession session = request.getSession();
                    session.invalidate();
                }
            })
            .logoutSuccessHandler(new LogoutSuccessHandler() { // 로그아웃 성공 후 핸들러
                @Override
                public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                    response.sendRedirect("/login");
                }
            })
        ;

        http
            .rememberMe() // remember me 기능 설정
            .rememberMeParameter("remember") // remember me parameter 설정 (default: remember-me)
            .tokenValiditySeconds(3600) // remember me token 만료 기간 (default: 14일)
            .userDetailsService(userDetailsService)
            ;

        return http.build();
    }
}
