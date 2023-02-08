package com.example.authorizationserver.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

@Entity(name = "clients")
@AllArgsConstructor
@NoArgsConstructor
@Data
public class Client {

    @Id
    private String id;

    private String clientId;
    private String clientSecret;
    private String redirectUri;
    private String scope;
    private String clientName;
    private String authenticationMethod;

    private String grantType;

    //Obicno bi se mapper pravio ali ovo da buse sto jednostavnije
    public static Client from(RegisteredClient client) {
        return new Client(
                client.getId(),
                client.getClientId(),
                client.getClientSecret(),
                client.getRedirectUris().stream().findAny().get(),
                client.getScopes().stream().findAny().get(),
                client.getClientName(),
                client.getClientAuthenticationMethods().stream().findAny().get().getValue(),
                client.getAuthorizationGrantTypes().stream().findAny().get().getValue()
        );
    }

    public static RegisteredClient to(Client client) {
        return RegisteredClient
                .withId(client.getId())
                .clientId(client.getClientId())
                .clientSecret(client.getClientSecret())
                .clientName(client.getClientName())
                .authorizationGrantType(new AuthorizationGrantType(client.getGrantType()))
                .clientAuthenticationMethod(new ClientAuthenticationMethod(client.getAuthenticationMethod()))
                .redirectUri(client.getRedirectUri())
                .scope(client.getScope())
                //ovo bi bilo u bazi ali zbog lakseg rada mi cemo vode direktno
                .tokenSettings(TokenSettings.builder()
                        //.accessTokenFormat(OAuth2TokenFormat.REFERENCE) //opaque
                        .build())

                .build();
    }

}
