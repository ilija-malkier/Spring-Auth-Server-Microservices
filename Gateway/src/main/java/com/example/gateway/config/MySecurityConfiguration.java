package com.example.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.stereotype.Component;

@Component
public class MySecurityConfiguration {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
      httpSecurity
              .authorizeHttpRequests(x->x.requestMatchers("/error").permitAll())
              .authorizeHttpRequests().anyRequest().authenticated()

              .and()

              .oauth2Login(x->x.loginPage("/oauth2/authorization/gateway"))
              .oauth2Client(Customizer.withDefaults());
        return httpSecurity.build();
    }
}
