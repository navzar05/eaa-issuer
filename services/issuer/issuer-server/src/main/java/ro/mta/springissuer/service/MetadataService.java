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
            // Initialize with empty map to avoid null pointer exceptions
            credentialConfigurations = new HashMap<>();
        }
    }


    public void reloadCredentialConfigurations() {
        loadCredentialConfigurations();
    }

    public Map<String, Object> getCredentialIssuerMetadata() {
        Map<String, Object> response = new HashMap<>();

        // Add standard metadata
        response.put("credential_issuer", serverConfig.getIssuerUrl());
        response.put("authorization_servers", List.of(serverConfig.getKeycloakBaseUrl() + "/realms/pid-issuer-realm"));
        response.put("credential_endpoint", serverConfig.getIssuerUrl() + "/wallet/credentialEndpoint");
        response.put("deferred_credential_endpoint", serverConfig.getIssuerUrl() + "/wallet/deferredEndpoint");
        response.put("notification_endpoint", serverConfig.getIssuerUrl() + "/wallet/notificationEndpoint");

        response.put("batch_credential_issuance", Map.of("batch_size", 10));
        response.put("credential_identifiers_supported", true);

        // Display Information
        response.put("display", List.of(
                Map.of(
                        "name", "Digital Credentials Issuer",
                        "locale", "en",
                        "logo", Map.of(
                                "uri", "https://"+ serverConfig.getServerAddress() + "/public/ic-logo.svg",
                                "alt_text", "EU Digital Identity Wallet Logo"
                        )
                )
        ));

        // Add the loaded credential configurations
        response.put("credential_configurations_supported", credentialConfigurations);

        response.put("openid4vci_version", "draft 14");

        return response;
    }

    public Map<String, Object> getCredentialConfiguration(String credentialType) {
        if (credentialConfigurations == null || !credentialConfigurations.containsKey(credentialType)) {
            return null;
        }
        return (Map<String, Object>) credentialConfigurations.get(credentialType);
    }
}