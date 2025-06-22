package ro.mta.springissuer.util.authzclient.registry;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;
import ro.mta.springissuer.util.authzclient.client.AuthzClient;
import ro.mta.springissuer.util.authzclient.client.AuthzClientKeycloak;
import ro.mta.springissuer.util.authzclient.client.AuthzClientSpring;

import java.util.HashMap;
import java.util.Map;

/**
 * Configurarea clientului prin intermediul căruia serviciul
 * {@link ro.mta.springissuer.service.UserInfoService} acesează
 * informațiile utilizatorilor de la sursa autentică.
 */
@Component
public class WebClientRegistry {

    @Value("${server.ssl.trust-store}")
    private Resource trustStore;

    @Value("${server.ssl.trust-store-password}")
    private String trustStorePassword;

    private final Map<String, AuthzClient> authzClientList;

    @Value("${keycloak.issuer.base-url}")
    private String keycloakBaseUrl;
    @Value("${keycloak.pid-issuer-srv.client-id}")
    private String keycloakClientId;
    @Value("${keycloak.pid-issuer-srv.client-secret}")
    private String keycloakClientSecret;
    @Value("${keycloak.token-url}")
    private String keycloakTokenUrl;
    @Value("${keycloak.admin-url:/admin/realms/pid-issuer-realm/users}")
    private String keycloakAdminUrl;

    @Value("${spring.authorization-server.base-url}")
    private String springBaseUrl;
    @Value("${spring.pid-issuer-srv.client-id}")
    private String springClientId;
    @Value("${spring.pid-issuer-srv.client-secret}")
    private String springClientSecret;
    @Value("${spring.token-url:/oauth2/token}")
    private String springTokenUrl;
    @Value("${spring.admin-url:/service/userinfo/}")
    private String springAdminUrl;


    public WebClientRegistry() {
        authzClientList = new HashMap<>();
    }

    @PostConstruct
    void init() {
        AuthzClientSpring authzClientSpring = new AuthzClientSpring(springBaseUrl,
                springClientId, springClientSecret, springTokenUrl, springAdminUrl, trustStore, trustStorePassword);

        AuthzClientKeycloak authzClientKeycloak = new AuthzClientKeycloak(keycloakBaseUrl,
                keycloakClientId, keycloakClientSecret, keycloakTokenUrl, keycloakAdminUrl, trustStore, trustStorePassword);

        authzClientList.put(springBaseUrl, authzClientSpring);
        authzClientList.put(keycloakBaseUrl, authzClientKeycloak);
    }

    public AuthzClient getAuthzClient(String issuerUrl) {
        return authzClientList.get(issuerUrl);
    }
}