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
import ro.mta.springissuer.util.encode.AgnosticSdJwtEncoder;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class CredentialService {
    private static final Logger logger = LoggerFactory.getLogger(CredentialService.class);

    @Value("${server.isdev:0}")
    private int IS_DEV;

    private final UserInfoService userInfoService;
    private final CredentialStatusService credentialStatusService;
    private final AgnosticSdJwtEncoder agnosticSdJwtEncoder;
    private final StrategyRegistry strategyRegistry;


    @Autowired
    public CredentialService(
            UserInfoService userInfoService,
            CredentialStatusService credentialStatusService,
            AgnosticSdJwtEncoder agnosticSdJwtEncoder,
            StrategyRegistry strategyRegistry

    ) {
        this.userInfoService = userInfoService;
        this.credentialStatusService = credentialStatusService;
        this.agnosticSdJwtEncoder = agnosticSdJwtEncoder;
        this.strategyRegistry = strategyRegistry;
    }


    public Map<String, Object> issueCredential(Jwt jwt, CredentialRequest request) {
        Long credentialId = null;
        try {
            // TODO: Verifica daca tipul de credential cerut este existent/aprobat
            credentialId = this.credentialStatusService.createCredentialStatus(false);

            if (credentialId == null) {
                throw new RuntimeException("Failed to generate credential id");
            }

            if (!strategyRegistry.supports(request.getVct())) {
                logger.error("{} not registered on issuer", request.getVct());
                if (IS_DEV==1) {
                    logger.info("Server is set to dev mode. Using agnostic sd-jwt encoder");
                    String sdJwt = agnosticSdJwtEncoder.encode(
                            userInfoService.getUserInfo(jwt),
                            credentialId
                    );
                } else
                    throw new RuntimeException("Server is not set to dev mode. Unregistered vct are not supported");
            }

            String sdJwt = strategyRegistry.getStrategy(request.getVct())
                    .encodeToSdJwt(
                            userInfoService.getUserInfo(jwt),
                            credentialId);

            logger.info("Successfully issued credential: {}",  credentialId);

            Map<String, Object> response = new HashMap<>();
            response.put("credential", sdJwt);
            return response;
        } catch (Exception e) {
            if (credentialId != null) {
                this.credentialStatusService.deleteCredentialStatus(credentialId);
            }
            throw new RuntimeException("Failed to issue credential", e);
        }
    }



    public void revokeCredential(Long credentialId) {
        logger.info("Revoking credential: {}", credentialId);
        credentialStatusService.updateCredentialStatus(credentialId, false);
    }
}