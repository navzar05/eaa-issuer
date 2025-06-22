package ro.mta.springissuer.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import ro.mta.springissuer.util.revocationlist.RevocationList;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.PrivateKey;
import java.text.ParseException;
import java.util.*;

@Service
public class RevocationListService {
    private static final Logger logger = LoggerFactory.getLogger(RevocationListService.class);

    private RevocationList revocationList;

    private String latestStatusListPath;

    @Value("${path.to.revocation.list.jwt.storage}")
    private String storagePath;

    @Value("${server.issuer-url}")
    private String credentialIssuerId;
    private final PrivateKey signingKey;
    private final List<Base64> signingCertificateChain;

    RevocationListService(RevocationList revocationList, PrivateKey signingKey, List<Base64> signingCertificateChain) {
        this.revocationList = revocationList;
        this.signingKey = signingKey;
        this.signingCertificateChain = signingCertificateChain;
    }

    @PostConstruct
    void init() {
        Path directory = Paths.get(storagePath);

        try{
            Optional<Path> newestFile = getNewestFile(directory);
            if (newestFile.isPresent()) {
                logger.info("Newest file found: {}", newestFile.get());
                latestStatusListPath = newestFile.get().toString();
            } else {
                logger.warn("No files found in directory: {}", directory);
            }
        } catch (IOException e) {
            logger.error("Error accessing directory: {}", directory, e);
        }
    }

    private Optional<Path> getNewestFile(Path directory) throws IOException {
        return Files.list(directory)
                .filter(Files::isRegularFile)
                .max(Comparator.comparingLong(this::getFileLastModified));
    }

    private long getFileLastModified(Path file) {
        try {
            return Files.readAttributes(file, BasicFileAttributes.class).lastModifiedTime().toMillis();
        } catch (IOException e) {
            logger.warn("Could not read file attributes for: {}", file, e);
            return 0;
        }
    }

    @Scheduled(cron = "0 0 0 * * *")
    public void generateStatusListJWT() {
        Map<String, Object> claims = new HashMap<>();
        Map<String, Object> statusListClaim = new HashMap<>();
        byte[] statusListCompressed = revocationList.getStatusListCompressed();

        statusListClaim.put("bits", 1);
        statusListClaim.put("lst", Base64.encode(statusListCompressed).toString());

        long iat = System.currentTimeMillis() / 1000;
        long exp = iat + 24 * 60 * 60;

        claims.put("iss", credentialIssuerId);
        claims.put("iat", iat);
        claims.put("exp", exp);
        claims.put("status_list", statusListClaim);

        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .x509CertChain(signingCertificateChain)
                    .type(new JOSEObjectType("statuslist+jwt"))
                    .build();

            JWTClaimsSet claimsSet = JWTClaimsSet.parse(claims);
            SignedJWT signedJWT = new SignedJWT(header, claimsSet);
            JWSSigner signer = new ECDSASigner(this.signingKey, Curve.P_256);
            signedJWT.sign(signer);
            String signedJwtString = signedJWT.serialize();
            logger.info("Successfully generated status list JWT");
            logger.debug("Signed JWT: {}", signedJwtString);

            String statusListId = UUID.randomUUID().toString();
            String statusListFileName = String.format("%s.jwt", statusListId);

            Path path = Paths.get(storagePath, statusListFileName);
            Files.createDirectories(path.getParent());
            Files.write(path, signedJwtString.getBytes());
            latestStatusListPath = String.valueOf(path.toAbsolutePath());
            logger.info("Successfully stored status list JWT in {}", latestStatusListPath);

        } catch (ParseException | JOSEException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void setCredentialStatus(long credentialId, boolean status) {
        this.revocationList.setStatus(BigInteger.valueOf(credentialId), status);
    }

    public String getStatusListPath() {
        return latestStatusListPath;
    }
}
