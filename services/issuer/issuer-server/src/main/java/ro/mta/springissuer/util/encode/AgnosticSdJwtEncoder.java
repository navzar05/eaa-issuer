package ro.mta.springissuer.util.encode;

import com.authlete.sd.SDJWT;
import com.authlete.sd.SDObjectBuilder;
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
import org.springframework.stereotype.Component;
import com.authlete.sd.Disclosure;

import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Component
public class AgnosticSdJwtEncoder {

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

    private final PrivateKey signingKey;
    private final List<Base64> signingCertificateChain;

    private final List<String> omittedDisclosuresList;

    public AgnosticSdJwtEncoder(PrivateKey signingKey, List<Base64> signingCertificateChain) {
        this.signingKey = signingKey;
        this.signingCertificateChain = signingCertificateChain;
        this.omittedDisclosuresList = new ArrayList<>();

        omittedDisclosuresList.add("vct");
    }

    public String encode(Map<String, Object> userDetails, Long credentialId) {
        List<Disclosure> disclosures = createDisclosures(userDetails);

        // TODO: Vezi ce faci cu vct sa fie mai safe
        return this.createSdJwt(userDetails.get("vct").toString(), credentialId, disclosures);
    }

    public List<Disclosure> createDisclosures(Map<String, Object> userDetails) {
        List<Disclosure> disclosures = new ArrayList<>();

        // TREBUIE SA OMITEM VCT DIN DISCLOSURES
        for (Map.Entry<String, Object> entry : userDetails.entrySet()) {
            String key = entry.getKey();

            boolean isOmitted = false;
            for (String disclosure : omittedDisclosuresList) {
                if (disclosure.equals(key)) {
                    isOmitted = true;
                    break;
                }
            }
            if (isOmitted) {
                continue;
            }

            Object value = entry.getValue();
            disclosures.add(new Disclosure(key, value));
        }

        return disclosures;
    }

    protected String createSdJwt(String vct, Long credentialId, List<Disclosure> disclosures) {
        SDObjectBuilder builder = new SDObjectBuilder();
        disclosures.forEach(builder::putSDClaim);

        Map<String, Object> claims = buildClaims(builder, vct, credentialId);

        try {
            SignedJWT signedJWT = createSignedJWT(claims);
            String signedJwtString = signedJWT.serialize();

            return new SDJWT(signedJwtString, disclosures).toString();
        } catch (JOSEException | ParseException e) {
            throw new RuntimeException("Failed to create SD-JWT", e);
        }
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

    private Map<String, Object> buildClaims(SDObjectBuilder builder, String vct, Long credentialId) {
        long currentTime = System.currentTimeMillis() / 1000;

        Map<String, Object> claims = builder.build();
        claims.put("iss", this.credentialIssuerId);
        claims.put("iat", currentTime);
        claims.put("exp", currentTime + FIVE_YEARS_IN_SECONDS);
        claims.put("vct", vct);
        claims.put("_sd_alg", builder.getHashAlgorithm());
        claims.put("status", createStatusClaims(credentialId));

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
                "idx", credentialId,
                "abi", abi,
                "ipfs_endpoint", "https://ipfs.io/ipfs/"
        );
        return Map.of(
                "status_list", statusList,
                "blockchain_list", blockchainList
        );
    }
}
