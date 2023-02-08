package com.example.client.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

import static com.fasterxml.jackson.databind.type.LogicalType.Collection;

@RestController
public class Controller {
//kako meni  da stigne token ovde?

    @GetMapping("/hello")
    public String hello(@AuthenticationPrincipal OidcUser oidcUser){

        WebClient build = WebClient.builder().build();
        String  block = build.get().uri("http://localhost:9090/demo").header(HttpHeaders.AUTHORIZATION, "Bearer "+oidcUser.getIdToken().getTokenValue())
                .retrieve()
                .bodyToMono(String.class)
                .block();
        return block.toString();
    }
}
