package ro.mta.springissuer.util.credential.pid;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDObjectBuilder;
import com.authlete.sd.SDJWT;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.util.Base64;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import ro.mta.springissuer.model.credential.Credential;
import ro.mta.springissuer.model.credential.Pid;

import ro.mta.springissuer.util.encode.AbstractEncoder;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.text.ParseException;
import java.time.Instant;
import java.util.*;

@Component
public class EncodePidInSdJwtVc extends AbstractEncoder {

    @Value("${revocation.list.link}")
    private String statusListLink;

    @Value("${revocation.list.ipfs.link}")
    private String ipfsListLink;

    public EncodePidInSdJwtVc(Provider pkcs11Provider,
                              KeyStore tokenKeyStore,
                              PrivateKey signingKey,
                              List<Base64> signingCertificateChain,
                              Signature tokenSignature) {
        super(pkcs11Provider, tokenKeyStore, signingKey, signingCertificateChain, tokenSignature);
    }

    @Override
    public String encode(Credential credential) {
        if (!(credential instanceof Pid pid)) {
            throw new IllegalArgumentException("Credential must be of type Pid");
        }
        return createSdJwt(pid);
    }

    private String createSdJwt(Pid pid) {

        List<Disclosure> disclosures = Arrays.asList(
                new Disclosure("family_name", pid.getFamilyName()),
                new Disclosure("given_name", pid.getGivenName()),
                new Disclosure("birthdate", pid.getBirthDate().toString()),
                //new Disclosure("credential_id", pid.getCredentialId()),
                new Disclosure("is_over_18", pid.getIsOver18()),
                new Disclosure("age_in_years", pid.getAgeInYears()),
                new Disclosure("issuing_authority", "Test PID Issuer"),
                new Disclosure("issuing_country", "RO")
        );

        SDObjectBuilder builder = new SDObjectBuilder();
        disclosures.forEach(builder::putSDClaim);

        // DE MODIFICAT
        long iat = System.currentTimeMillis() / 1000;
        long exp = iat + 5 * 365 * 24 * 60 * 60;

        Map<String, Object> statusList = new HashMap<>();
        Map<String, Object> ipfsList = new HashMap<>();
        Map<String, Object> status = new HashMap<>();

        statusList.put("uri", statusListLink);
        statusList.put("idx", pid.getCredentialId());

        ipfsList.put("uri", ipfsListLink);
        ipfsList.put("id", pid.getCredentialId());

        status.put("status_list", statusList);
        status.put("ipfs_list", ipfsList);
        // Claim-uri standard
        Map<String, Object> claims = builder.build();
        claims.put("iss", this.getCredentialIssuerId());
        claims.put("iat", iat);
        claims.put("exp", exp);
        claims.put("vct", pid.getVct());
        claims.put("_sd_alg", builder.getHashAlgorithm());
        claims.put("status", status);



        try {
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .x509CertChain(this.getSigningCertificateChain())
                    .type(new com.nimbusds.jose.JOSEObjectType("vc+sd-jwt"))
                    .build();

            JWTClaimsSet claimsSet = JWTClaimsSet.parse(claims);
            SignedJWT signedJWT = new SignedJWT(header, claimsSet);

            JWSSigner signer = new ECDSASigner(this.getSigningKey(), Curve.P_256);
            signedJWT.sign(signer);
            String signedJwtString = signedJWT.serialize();
            SDJWT sdJwt = new SDJWT(signedJwtString, disclosures);
            return sdJwt.toString();
        } catch (JOSEException | ParseException e) {
            throw new RuntimeException(e);
        }
    }


}