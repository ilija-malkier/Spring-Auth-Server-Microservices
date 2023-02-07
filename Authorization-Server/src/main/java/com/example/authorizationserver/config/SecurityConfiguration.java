package com.example.authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfiguration {


    @Bean
    public SecurityFilterChain appSecurtyFilterChain(HttpSecurity httpSecurity) throws Exception {

        //ovo je login forma autorizacionog servera to je google login kada nas redirect na nju
        httpSecurity.formLogin()
                .and()
                .authorizeHttpRequests(x -> x.requestMatchers("/well-known/openid-configuration").permitAll())
                .authorizeHttpRequests().anyRequest().authenticated();

        return httpSecurity.build();
    }

    //Replaced with db
//    @Bean
//    public UserDetailsService userDetailsService(){
//        UserDetails userDetails= User
//                .withUsername("ilija")
//                .password("1234")
//                .roles("admin")
//                .authorities("admin")
//                .build();
//
//        return new InMemoryUserDetailsManager(userDetails);
//    }
    //same encoder is applied on client secret  and user password
    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }


}
