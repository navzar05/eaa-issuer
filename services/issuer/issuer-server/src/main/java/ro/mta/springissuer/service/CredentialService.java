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

    private final UserInfoService userInfoService;
    private final CredentialStatusService credentialStatusService;
    private final AgnosticSdJwtEncoder agnosticSdJwtEncoder;


    @Autowired
    public CredentialService(
            UserInfoService userInfoService,
            CredentialStatusService credentialStatusService,
            AgnosticSdJwtEncoder agnosticSdJwtEncoder

    ) {
        this.userInfoService = userInfoService;
        this.credentialStatusService = credentialStatusService;
        this.agnosticSdJwtEncoder = agnosticSdJwtEncoder;
    }


    public Map<String, Object> issueCredential(Jwt jwt, CredentialRequest request) {
        try {
            //TODO: Verifica daca tipul de credential cerut este existent/aprobat
            Long credentialId = this.credentialStatusService.createCredentialStatus(false);

            if (credentialId == null) {
                throw new RuntimeException("Failed to generate credential id");
            }

//            String sdJwt = strategyRegistry.getStrategy(request.getVct())
//                    .encodeToSdJwt(
//                            userInfoService.getUserDetails(jwt),
//                            credentialId);

            String sdJwt = agnosticSdJwtEncoder.encode(
                    userInfoService.getUserDetails(jwt),
                    credentialId
            );

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