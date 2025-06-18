package ro.mta.springissuer.service;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import ro.mta.springissuer.entity.CredentialStatus;
import ro.mta.springissuer.model.request.CredentialRequest;
import ro.mta.springissuer.util.credential.StrategyRegistry;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class CredentialService {
    private static final Logger logger = LoggerFactory.getLogger(CredentialService.class);

    @Value("${revocation.list.size}")
    private int CREDENTIAL_ID_MAX;

    @Value("${path.to.revocation.list}")
    public String credentialStatusFile;


    private final UserInfoService userInfoService;
    private final StrategyRegistry strategyRegistry;
    private final CredentialStatusService credentialStatusService;


    @Autowired
    public CredentialService(
            UserInfoService userInfoService,
            StrategyRegistry strategyRegistry,
            CredentialStatusService credentialStatusService
    ) {
        this.userInfoService = userInfoService;
        this.strategyRegistry = strategyRegistry;
        this.credentialStatusService = credentialStatusService;
    }


    public Map<String, Object> issueCredential(Jwt jwt, CredentialRequest request) {
        try {
            if (!strategyRegistry.supports(request.getVct())) {
                return null;
            }

            Long credentialId = this.credentialStatusService.createCredentialStatus(false);

            if (credentialId == null) {
                throw new RuntimeException("Failed to generate credential id");
            }

            String sdJwt = strategyRegistry.getStrategy(request.getVct())
                    .encodeToSdJwt(
                            userInfoService.getUserDetails(jwt),
                            credentialId);

            logger.info("Successfully issued credential: {}",  credentialId);

            Map<String, Object> response = new HashMap<>();
            response.put("credential", sdJwt);
            return response;
        } catch (Exception e) {
            throw new RuntimeException("Failed to issue credential", e);
        }
    }



    public void revokeCredential(Long credentialId) {
        logger.info("Revoking credential: {}", credentialId);
        credentialStatusService.updateCredentialStatus(credentialId, false);
    }
}