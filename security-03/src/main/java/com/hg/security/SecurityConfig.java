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
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests()
            .anyRequest().authenticated();

        http
            .formLogin();

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
            .deleteCookies("remember-me") // 로그아웃 후 쿠키 삭제
        ;

        return http.build();
    }
}
