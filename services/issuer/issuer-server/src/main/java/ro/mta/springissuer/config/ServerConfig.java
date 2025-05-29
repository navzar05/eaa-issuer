package ro.mta.springissuer.config;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@Getter
public class ServerConfig {
    @Value("${server.address}")
    private String serverAddress;

    @Value("${server.port}")
    private String serverPort;

    @Value("${server.issuer-url}")
    private String issuerUrl;

    @Value("${keycloak.base-url}")
    private String keycloakBaseUrl;


}
