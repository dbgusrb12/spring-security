package com.hg.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

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
            .formLogin();

        http
            .rememberMe() // remember me 기능 설정
            .rememberMeParameter("remember") // remember me parameter 설정 (default: remember-me)
            .tokenValiditySeconds(3600) // remember me token 만료 기간 (default: 14일)
            .userDetailsService(userDetailsService)
        ;

        return http.build();
    }
}
