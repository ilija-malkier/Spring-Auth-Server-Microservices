package com.example.authorizationserver.config;

import com.example.authorizationserver.keys.JwksKeys;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.Collection;

@Configuration
public class TokenConfiguration {

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        //key set je jer je ovo set pa moze da ima vise keypaira pa moze da ih rotira

        RSAKey rsaKey = JwksKeys.generateRSAKey();
        JWKSet set = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(set);
    }


    //requeired for openid scope to work
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    //Customise returning id token
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return context -> {

            context.getClaims().claim("test", "test");
            Collection<? extends GrantedAuthority> authorities = context.getPrincipal().getAuthorities();//list of GranterAuthority
            context.getClaims().claim("authorities",authorities.stream().map(a->a.getAuthority()).toList());
        };

    }
}
