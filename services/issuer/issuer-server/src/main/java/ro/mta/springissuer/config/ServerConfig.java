package ro.mta.springissuer.config;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Clasă care conține șiruri de carctere specifice server-ului
 * care trebuie folosite în raspunsurile oferite de acesta
 * pentru a ghida traficul în infrastructură.
 */
@Component
@Getter
public class ServerConfig {
    @Value("${server.address}")
    private String serverAddress;

    @Value("${server.port}")
    private String serverPort;

    @Value("${server.issuer-url}")
    private String issuerUrl;

    @Value("${server.public-issuer-url}")
    private String publicIssuerUrl;

    @Value("${keycloak.base-url}")
    private String keycloakBaseUrl;


}
