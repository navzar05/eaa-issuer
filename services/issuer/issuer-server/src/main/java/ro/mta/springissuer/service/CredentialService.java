package ro.mta.springissuer.service;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
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


    private int nextCredentialId = 0;

    private final Map<String, Integer> credentialStatusMap = new HashMap<>();

    private final UserInfoService userInfoService;
    private final StrategyRegistry strategyRegistry;
    private final RevocationListService revocationListService;
    private final IpfsService ipfsService;

    @Autowired
    public CredentialService(
            UserInfoService userInfoService,
            StrategyRegistry strategyRegistry,
            RevocationListService revocationListService,
            IpfsService ipfsService
    ) {
        this.userInfoService = userInfoService;
        this.strategyRegistry = strategyRegistry;
        this.revocationListService = revocationListService;
        this.ipfsService = ipfsService;

    }


    @PostConstruct
    private void initializeCredentialStatusTracking() {
        try {
            logger.info("Initializing credential status tracking from {}", credentialStatusFile);
            Path path = Paths.get(credentialStatusFile);
            if (Files.exists(path)) {
                try (BufferedReader reader = new BufferedReader(new FileReader(credentialStatusFile))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        String[] parts = line.split(":");
                        if (parts.length == 2) {
                            String credentialId = parts[0];
                            int status = Integer.parseInt(parts[1]);
                            credentialStatusMap.put(credentialId, status);
                            revocationListService.setCredentialStatus(Long.parseLong(credentialId), status == 1);
                        }
                    }
                }

                credentialStatusMap.keySet().stream()
                        .mapToInt(Integer::parseInt)
                        .max()
                        .ifPresent(maxId -> nextCredentialId = maxId + 1);
                logger.info("Loaded {} credentials from status file", credentialStatusMap.size());
            } else {
                logger.info("Credential status file not found, will create a new one when needed");
            }

            this.revocationListService.generateStatusListJWT();
            logger.info("Credential status tracking initialized");
            // TODO: trebuie repornit
            // this.ipfsService.sendCascadeToIpfs();
            // logger.info("IPFS cascade sent");
        } catch (IOException e) {
            logger.error("Error initializing credential status tracking: {}", e.getMessage(), e);
        }
    }

    public Map<String, Object> issueCredential(Jwt jwt, CredentialRequest request) {
        try {
            if (!strategyRegistry.supports(request.getVct())) {
                return null;
            }

            if (nextCredentialId + 1 > CREDENTIAL_ID_MAX) {
                logger.error("Credential ID limit reached, please refresh credential status file and try again");
                return null;
            }
            String credentialId = String.valueOf(nextCredentialId++);
            logger.info("Issuing credential: {}", credentialId);

            String sdJwt = strategyRegistry.getStrategy(request.getVct())
                    .encodeToSdJwt(
                            userInfoService.getUserDetails(jwt),
                            credentialId);


            credentialStatusMap.put(credentialId, 0);

            logger.info("Successfully issued credential: {}", credentialId);

            updateCredentialStatusFile();

//            ipfsService.sendCascadeToIpfs();

            Map<String, Object> response = new HashMap<>();
            response.put("credential", sdJwt);
            return response;
        } catch (Exception e) {
            throw new RuntimeException("Failed to issue credential", e);
        }
    }

    public void updateCredentialStatusFile() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(credentialStatusFile))) {
            for (Map.Entry<String, Integer> entry : credentialStatusMap.entrySet()) {
                writer.write(entry.getKey() + ":" + entry.getValue());
                writer.newLine();
            }
            logger.info("Updated credential status file with {} credentials", credentialStatusMap.size());
        } catch (IOException e) {
            logger.error("Error writing to credential status file: {}", e.getMessage(), e);
        }
    }

    private boolean isCredentialIdUsed(String credentialId)
    {
        return credentialStatusMap.containsKey(credentialId);
    }

    public void revokeCredential(ConcurrentHashMap<String, Integer> credentialStatusMap,
                                 String credentialId) {
        logger.info("Revoking credential: {}", credentialId);
        credentialStatusMap.put(credentialId, 1);
        updateCredentialStatusFile();
        revocationListService.setCredentialStatus(Long.parseLong(credentialId), true);
    }
}