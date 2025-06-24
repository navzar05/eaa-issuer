package ro.mta.springissuer.util.encode.graduation;

import com.authlete.sd.Disclosure;
import com.nimbusds.jose.util.Base64;
import org.springframework.stereotype.Component;

import ro.mta.springissuer.model.credential.Credential;
import ro.mta.springissuer.model.credential.UniversityGraduation;
import ro.mta.springissuer.util.encode.AbstractSdJwtEncoder;

import java.security.*;
import java.util.*;


@Component("graduationEncoder")
public class UnivGradSdJwtEncoder extends AbstractSdJwtEncoder {

    public UnivGradSdJwtEncoder(PrivateKey signingKey, List<Base64> signingCertificateChain) {
        super(signingKey, signingCertificateChain);
    }

    @Override
    public String encode(Map<String, Object> userDetails, Long credentialId) {
        UniversityGraduation universityGraduation = new UniversityGraduation(userDetails, credentialId);
        return createSdJwt(universityGraduation, createDisclosures(universityGraduation));
    }

    protected List<Disclosure> createDisclosures(Credential credential) {
        UniversityGraduation graduation = (UniversityGraduation) credential;

        return Arrays.asList(
                new Disclosure("family_name", graduation.getFamilyName()),
                new Disclosure("given_name", graduation.getGivenName()),
                new Disclosure("graduation_year", graduation.getGraduationYear()),
                new Disclosure("student_id", graduation.getStudentId()),
                new Disclosure("university", graduation.getUniversity()),
                new Disclosure("issuance_date", graduation.getIssuanceDate().toString()),
                new Disclosure("expiry_date", graduation.getExpiryDate()),
                new Disclosure("is_student", graduation.isStudent()),
                new Disclosure("certificate_type", graduation.getVct()),
                new Disclosure("issuing_country", "RO")
        );
    }
}