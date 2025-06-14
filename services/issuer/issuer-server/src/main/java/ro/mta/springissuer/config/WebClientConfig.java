package ro.mta.springissuer.config;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.security.KeyStore;

/**
 * Configurarea clientului prin intermediul căruia serviciul
 * {@link ro.mta.springissuer.service.UserInfoService} acesează
 * informațiile utilizatorilor de la sursa autentică.
 */
@Configuration
public class WebClientConfig {

    @Value("${keycloak.base-url}")
    private String keycloakBaseUrl;

    @Value("${spring.security.oauth2.resourceserver.jwt.spring-authz.issuer-uri}")
    private String springAuthzBaseUrl;

    @Value("${server.ssl.trust-store}")
    private Resource trustStore;

    @Value("${server.ssl.trust-store-password}")
    private String trustStorePassword;

    /**
     * WebClient pentru comunicarea cu Keycloak (pentru credentialele PID)
     */
    @Bean(name = "keycloakWebClient")
    public WebClient keycloakWebClient() throws Exception {
        return createSecureWebClient(keycloakBaseUrl);
    }

    /**
     * WebClient pentru comunicarea cu Spring Authorization Server (pentru credentialele universitare)
     */
    @Bean(name = "springAuthzWebClient")
    public WebClient springAuthzWebClient() throws Exception {
        return createSecureWebClient(springAuthzBaseUrl);
    }

    /**
     * Metodă helper pentru crearea unui WebClient cu SSL configurat
     */
    private WebClient createSecureWebClient(String baseUrl) throws Exception {
        KeyStore trustStoreObj = KeyStore.getInstance("PKCS12");
        try (InputStream trustStoreStream = trustStore.getInputStream()) {
            trustStoreObj.load(trustStoreStream, trustStorePassword.toCharArray());
        }

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStoreObj);

        SslContext sslContext = SslContextBuilder.forClient()
                .trustManager(trustManagerFactory)
                .build();

        HttpClient httpClient = HttpClient.create()
                .secure(t -> t.sslContext(sslContext));

        return WebClient.builder()
                .baseUrl(baseUrl)
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
    }
}