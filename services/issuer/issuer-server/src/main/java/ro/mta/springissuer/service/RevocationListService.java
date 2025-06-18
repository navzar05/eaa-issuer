package ro.mta.springissuer.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
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
import java.security.PrivateKey;
import java.text.ParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

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
