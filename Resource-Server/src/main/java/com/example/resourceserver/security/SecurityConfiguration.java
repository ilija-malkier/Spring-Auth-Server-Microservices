package com.example.resourceserver.security;

import com.example.resourceserver.converter.CustomJwtAuthenticationTokenConverter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfiguration {


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
//        httpSecurity
//                //Non-Opaque tokens
////                //act like a resource server
//                .oauth2ResourceServer(
//                        //validate with jwt
////                        r->r.jwt()
////                                //public key endpoint to get to validate jwt
////                                .jwkSetUri("http://localhost:8080/oauth2/jwks")
////                                .jwtAuthenticationConverter(new CustomJwtAuthenticationTokenConverter())
//                ).jwt();
/////             Opaque tokens
////        .oauth2ResourceServer(x->
////                x.opaqueToken()
////
////                        //treba na uri introspection pointa
////                        .introspectionUri("http://127.0.0.1:8080/oauth2/introspect")
////                        //ovo su kredencijali  jer mi kada preko postmana saljemo request mi imamo auth podesen na basic ,client id i client secret mora da se salju
////                        .introspectionClientCredentials("client","secret")
////        );
//
//        httpSecurity
//                .authorizeHttpRequests()
//                .anyRequest().authenticated();

        httpSecurity.authorizeHttpRequests(x->x.requestMatchers("/**").permitAll())

                .oauth2ResourceServer()
                .jwt();
        return httpSecurity.build();
    }
}
