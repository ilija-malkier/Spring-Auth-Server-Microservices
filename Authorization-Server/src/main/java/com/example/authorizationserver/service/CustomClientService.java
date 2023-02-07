package com.example.authorizationserver.service;

import com.example.authorizationserver.entity.Client;
import com.example.authorizationserver.repository.ClientRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class CustomClientService implements RegisteredClientRepository {
    private ClientRepository clientRepository;

    @Override
    public void save(RegisteredClient registeredClient) {
        clientRepository.save(Client.from(registeredClient));
    }

    @Override
    public RegisteredClient findById(String id) {
        return Client.to(clientRepository.findById(id).get());
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return Client.to(clientRepository.findByClientId(clientId).get());
    }
}
