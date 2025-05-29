package ro.mta.springissuer.util.credential.graduation;

import com.authlete.sd.Disclosure;
import com.authlete.sd.SDObjectBuilder;
import com.authlete.sd.SDJWT;
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
import org.springframework.stereotype.Component;

import ro.mta.springissuer.model.credential.Credential;
import ro.mta.springissuer.model.credential.UniversityGraduation;
import ro.mta.springissuer.util.encode.AbstractEncoder;

import java.security.*;
import java.text.ParseException;
import java.util.*;

@Component("graduationEncoder")
public class EncodeGraduationInSdJwtVc extends AbstractEncoder {

    @Value("${revocation.list.link}")
    private String revocationListLink;

    @Value("${revocation.list.ipfs.link}")
    private String ipfsListLink;

    public EncodeGraduationInSdJwtVc(Provider pkcs11Provider, KeyStore tokenKeyStore, PrivateKey signingKey, List<Base64> signingCertificateChain, Signature tokenSignature) {
        super(pkcs11Provider, tokenKeyStore, signingKey, signingCertificateChain, tokenSignature);
    }

    @Override
    public String encode(Credential credential) {
        if (!(credential instanceof UniversityGraduation universityGraduation)) {
            throw new IllegalArgumentException("Credential must be of type Pid");
        }
        return createSdJwt(universityGraduation);
    }

    private String createSdJwt(UniversityGraduation graduation) {
        // Create disclosures for selectively disclosable claims
        List<Disclosure> disclosures = Arrays.asList(
                new Disclosure("family_name", graduation.getFamilyName()),
                new Disclosure("given_name", graduation.getGivenName()),
                new Disclosure("graduation_year", graduation.getGraduationYear()),
                new Disclosure("student_id", graduation.getStudentId()),
                new Disclosure("university", graduation.getUniversity()),
                new Disclosure("issuance_date", graduation.getIssuanceDate().toString()),
                new Disclosure("expiry_date", graduation.getExpiryDate()),
                // new Disclosure("credential_id", graduation.getCredentialId()),
                new Disclosure("is_student", graduation.getIsStudent()),
                new Disclosure("certificate_type", graduation.getVct()),
                new Disclosure("issuing_country", "RO")
        );


        // DE MODIFICAT
        long iat = System.currentTimeMillis() / 1000;
        long exp = iat + 5 * 365 * 24 * 60 * 60;

        SDObjectBuilder builder = new SDObjectBuilder();
        disclosures.forEach(builder::putSDClaim);

        Map<String, Object> statusList = new HashMap<>();
        Map<String, Object> ipfsList = new HashMap<>();
        Map<String, Object> status = new HashMap<>();

        statusList.put("uri", revocationListLink);
        statusList.put("idx", graduation.getCredentialId());

        ipfsList.put("uri", ipfsListLink);
        ipfsList.put("id", graduation.getCredentialId());


        status.put("status_list", statusList);
        status.put("ipfs_list", ipfsList);
        // Claim-uri standard
        Map<String, Object> claims = builder.build();
        claims.put("iss", this.getCredentialIssuerId());
        claims.put("iat", iat);
        claims.put("exp", exp);
        claims.put("vct", graduation.getVct());
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
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException(e);
        }
    }

}