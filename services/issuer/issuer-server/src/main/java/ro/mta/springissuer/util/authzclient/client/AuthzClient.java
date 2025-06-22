package ro.mta.springissuer.util.authzclient.client;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import ro.mta.springissuer.service.UserInfoService;

import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Map;

@Getter
public abstract class AuthzClient {

    protected static final Logger logger = LoggerFactory.getLogger(UserInfoService.class);

    private WebClient webClient;
    private final String clientId;
    private final String clientSecret;
    private final String tokenUrl;
    private final String adminUrl;
    private final String baseUrl;
    private final Resource trustStore;
    private final String trustStorePassword;

    public AuthzClient(String baseUrl,
                       String clientId,
                       String clientSecret,
                       String tokenUrl,
                       String adminUrl,
                       Resource trustStore,
                       String trustStorePassword) {

            this.baseUrl = baseUrl;
            this.clientId = clientId;
            this.clientSecret = clientSecret;
            this.tokenUrl = tokenUrl;
            this.adminUrl = adminUrl;
            this.trustStore = trustStore;
            this.trustStorePassword = trustStorePassword;
            try {
                this.webClient = createSecureWebClient(this.baseUrl);
            }
            catch (Exception e) {
                throw new RuntimeException(e);
            }
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

    protected abstract String getAdminToken();
    public abstract Map<String, Object> getUserDetails(String userId);
}
