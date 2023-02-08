package com.example.authorizationserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

@Configuration
public class AuthorizationServerConfiguration {

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain asSecurtyFilterChain(HttpSecurity httpSecurity) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(httpSecurity);
        //enable open id connect
        httpSecurity.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults());

        httpSecurity.exceptionHandling(
                e -> e.authenticationEntryPoint(
                        //vidi koje sve imamo AuthenticationEntryPoint
                        new LoginUrlAuthenticationEntryPoint("/login")
                )
        );
        return httpSecurity.build();
    }

    //Replaced with db
//    @Bean
//    public RegisteredClientRepository registeredClientRepository(){
//        RegisteredClient registeredClient=RegisteredClient
//                .withId(UUID.randomUUID().toString())
//                .clientId("client")
//                .clientSecret("secret")
//                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
//                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
//                .scope(OidcScopes.OPENID)
//                //should not use localhost,baca exeption nije dozvoljeno
//                .redirectUri("https://springone.io/authorized")
//                .redirectUri("http://127.0.0.1:8080/auth")
//                .tokenSettings(TokenSettings.builder()
//                        //Menjamo da li je opaque ili non-opaque
//                        //Opaque je REFERENCE
//                        //Non-Opaque je SELF_CONTAINED
//                        //.accessTokenFormat(OAuth2TokenFormat.REFERENCE)
//
//                        .build())
//
//                .build();
//
//        return new InMemoryRegisteredClientRepository(registeredClient);
//    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().issuer("http://127.0.0.1:8080").build();
    }

}
