package ro.mta.springissuer.util.encode;


import com.authlete.sd.Disclosure;
import com.authlete.sd.SDObjectBuilder;
import com.authlete.sd.SDJWT;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ClassPathResource;
import org.springframework.util.ResourceUtils;
import ro.mta.springissuer.model.credential.Credential;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public abstract class AbstractSdJwtEncoder {

    private static final long FIVE_YEARS_IN_SECONDS = 5L * 365 * 24 * 60 * 60;

    @Value("${revocation.list.link}")
    protected String revocationListLink;

    @Value("${server.issuer-url}")
    private String credentialIssuerId;
    @Value("${token.enabled:false}")
    private boolean tokenEnabled;

    @Value("${blockchain.contract.address}")
    private String blockchainContractAddress;

    @Value("${blockchain.issuer.address}")
    private String blockchainIssuerAddress;

    private final Provider pkcs11Provider;
    private final KeyStore tokenKeyStore;
    private final PrivateKey signingKey;
    private final List<Base64> signingCertificateChain;
    private final Signature tokenSignature;


    public AbstractSdJwtEncoder(Provider pkcs11Provider, KeyStore tokenKeyStore,
                                PrivateKey signingKey, List<Base64> signingCertificateChain,
                                Signature tokenSignature) {
        this.pkcs11Provider = pkcs11Provider;
        this.tokenKeyStore = tokenKeyStore;
        this.signingKey = signingKey;
        this.signingCertificateChain = signingCertificateChain;
        this.tokenSignature = tokenSignature;
    }

    protected String createSdJwt(Credential credential, List<Disclosure> disclosures) {
        SDObjectBuilder builder = new SDObjectBuilder();
        disclosures.forEach(builder::putSDClaim);

        Map<String, Object> claims = buildClaims(builder, credential);

        try {
            SignedJWT signedJWT = createSignedJWT(claims);
            String signedJwtString = signedJWT.serialize();

            return new SDJWT(signedJwtString, disclosures).toString();
        } catch (JOSEException | ParseException e) {
            throw new RuntimeException("Failed to create SD-JWT", e);
        }
    }

    private Map<String, Object> buildClaims(SDObjectBuilder builder, Credential credential) {
        long currentTime = System.currentTimeMillis() / 1000;

        Map<String, Object> claims = builder.build();
        claims.put("iss", this.credentialIssuerId);
        claims.put("iat", currentTime);
        claims.put("exp", currentTime + FIVE_YEARS_IN_SECONDS);
        claims.put("vct", credential.getVct());
        claims.put("_sd_alg", builder.getHashAlgorithm());
        claims.put("status", createStatusClaims(credential.getCredentialId()));

        return claims;
    }

    private Map<String, Object> createStatusClaims(Long credentialId) {
        Map<String, Object> statusList = Map.of(
                "uri", revocationListLink,
                "idx", credentialId
        );

        ObjectMapper objectMapper = new ObjectMapper();
        List<Map<String, Object>> abi;
        try {
            ClassPathResource resource = new ClassPathResource("blockchain-abi.json");
            abi = objectMapper.readValue(
                    resource.getInputStream(),
                    new TypeReference<List<Map<String, Object>>>() {
                    }
            );

            // Clean, parsed objects - no escape characters
            abi.forEach(item -> {
                System.out.println("Type: " + item.get("type"));
                System.out.println("Name: " + item.get("name"));
            });

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        Map<String, Object> blockchainList = Map.of(
                "contract_address", blockchainContractAddress,
                "issuer_address", blockchainIssuerAddress,
                "abi", abi
        );
        return Map.of(
                "status_list", statusList,
                "blockchain_list", blockchainList
        );
    }

    private SignedJWT createSignedJWT(Map<String, Object> claims) throws ParseException, JOSEException {
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .x509CertChain(this.signingCertificateChain)
                .type(new com.nimbusds.jose.JOSEObjectType("vc+sd-jwt"))
                .build();

        JWTClaimsSet claimsSet = JWTClaimsSet.parse(claims);
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);

        JWSSigner signer = new ECDSASigner(this.signingKey, Curve.P_256);
        signedJWT.sign(signer);

        return signedJWT;
    }

    protected abstract List<Disclosure> createDisclosures(Credential credential);

    public abstract String encode(Credential credential);
}