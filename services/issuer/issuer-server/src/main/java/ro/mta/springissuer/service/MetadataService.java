package ro.mta.springissuer.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;
import ro.mta.springissuer.config.ServerConfig;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


@Service
public class MetadataService {
    private static final Logger logger = LoggerFactory.getLogger(MetadataService.class);

    private final ServerConfig serverConfig;
    private final ResourceLoader resourceLoader;
    private final ObjectMapper objectMapper;

    @Value("${metadata.config.path:classpath:config/credential-configurations.json}")
    private String metadataConfigPath;

    @Value("${spring.authorization-server.base-url:https://192.168.1.137:9000}")
    private String springAuthServerUrl;

    private Map<String, Object> credentialConfigurations;

    @Autowired
    public MetadataService(ServerConfig serverConfig, ResourceLoader resourceLoader, ObjectMapper objectMapper) {
        this.serverConfig = serverConfig;
        this.resourceLoader = resourceLoader;
        this.objectMapper = objectMapper;
    }

    @PostConstruct
    public void init() {
        loadCredentialConfigurations();
    }

    private void loadCredentialConfigurations() {
        try {
            Resource resource = resourceLoader.getResource(metadataConfigPath);
            try (InputStream inputStream = resource.getInputStream()) {
                credentialConfigurations = objectMapper.readValue(inputStream, Map.class);
                logger.info("Successfully loaded credential configurations from {}", metadataConfigPath);
            }
        } catch (IOException e) {
            logger.error("Failed to load credential configurations from {}", metadataConfigPath, e);
            credentialConfigurations = new HashMap<>();
        }
    }

    public void reloadCredentialConfigurations() {
        loadCredentialConfigurations();
    }

    public Map<String, Object> getCredentialIssuerMetadata() {
        Map<String, Object> response = new HashMap<>();

        // Add standard metadata with multiple authorization servers
        response.put("credential_issuer", serverConfig.getIssuerUrl());

        // Support both Keycloak and Spring Authorization Server
        response.put("authorization_servers", List.of(
                springAuthServerUrl,
                serverConfig.getKeycloakBaseUrl() + "/realms/pid-issuer-realm"


        ));

        response.put("credential_endpoint", serverConfig.getIssuerUrl() + "/wallet/credentialEndpoint");
        response.put("deferred_credential_endpoint", serverConfig.getIssuerUrl() + "/wallet/deferredEndpoint");
        response.put("notification_endpoint", serverConfig.getIssuerUrl() + "/wallet/notificationEndpoint");

        response.put("batch_credential_issuance", Map.of("batch_size", 10));
        response.put("credential_identifiers_supported", true);

        // Enhanced display information
        response.put("display", List.of(
                Map.of(
                        "name", "Credentials Issuer",
                        "locale", "en",
                        "logo", Map.of(
                                "uri", serverConfig.getIssuerUrl() + "/assets/logo.png",
                                "alt_text", "Digital Credentials Issuer Logo"
                        )
                )
        ));

        // Enhanced credential configurations with authorization server mapping
        Map<String, Object> enhancedConfigurations = enhanceCredentialConfigurations();
        response.put("credential_configurations_supported", enhancedConfigurations);

        response.put("openid4vci_version", "draft 14");

        return response;
    }

    private Map<String, Object> enhanceCredentialConfigurations() {
        Map<String, Object> enhanced = new HashMap<>(credentialConfigurations);

        // Add authorization server mapping for each credential type
        for (Map.Entry<String, Object> entry : enhanced.entrySet()) {
            String credentialType = entry.getKey();
            Map<String, Object> config = (Map<String, Object>) entry.getValue();

            // Add the authorization_server field based on credential type
            String authorizationServer = getAuthorizationServerForCredential(credentialType);
            config.put("authorization_server", authorizationServer);

            logger.debug("Enhanced credential configuration '{}' with authorization_server: {}",
                    credentialType, authorizationServer);
        }

        logger.info("Enhanced {} credential configurations with authorization_server mappings",
                enhanced.size());

        return enhanced;
    }

    public Map<String, Object> getCredentialConfiguration(String credentialType) {
        if (credentialConfigurations == null || !credentialConfigurations.containsKey(credentialType)) {
            return null;
        }
        return (Map<String, Object>) credentialConfigurations.get(credentialType);
    }

    public String getAuthorizationServerForCredential(String credentialType) {
        if (credentialType.contains("university_graduation")) {
            return springAuthServerUrl;
        } else {
            return serverConfig.getKeycloakBaseUrl() + "/realms/pid-issuer-realm";
        }
    }
}
