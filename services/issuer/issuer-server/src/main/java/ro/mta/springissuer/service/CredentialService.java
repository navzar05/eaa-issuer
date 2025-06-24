package ro.mta.springissuer.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import ro.mta.springissuer.model.request.CredentialRequest;
import ro.mta.springissuer.util.encode.EncoderRegistry;

import java.util.*;

@Service
public class CredentialService {
    private static final Logger logger = LoggerFactory.getLogger(CredentialService.class);


    @Value("${server.isdev:0}")
    private int isDev;

    private final UserInfoService userInfoService;
    private final CredentialStatusService credentialStatusService;
    private final EncoderRegistry encoderRegistry;


    @Autowired
    public CredentialService(
            UserInfoService userInfoService,
            CredentialStatusService credentialStatusService,
            EncoderRegistry encoderRegistry

    ) {
        this.userInfoService = userInfoService;
        this.credentialStatusService = credentialStatusService;
        this.encoderRegistry = encoderRegistry;
    }


    public Map<String, Object> issueCredential(Jwt jwt, CredentialRequest request) {
        Long credentialId = null;
        try {
            // TODO: Verifica daca tipul de credential cerut este existent/aprobat
            credentialId = this.credentialStatusService.createCredentialStatus(false);

            String sdJwt = null;

            if (credentialId == null) {
                throw new RuntimeException("Failed to generate credential id");
            }

            if (!encoderRegistry.containsEncoder(request.getVct())) {
                logger.error("{} not registered on issuer", request.getVct());
                throw new RuntimeException("Credential is not registered on issuer");

            } else {
                sdJwt = encoderRegistry.
                        getEncoder(request.getVct()).
                        encode(userInfoService.getUserInfo(jwt),
                                credentialId);
            }

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