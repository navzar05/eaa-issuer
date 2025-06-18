package ro.mta.springissuer.model.credential;

import lombok.Builder;
import lombok.Getter;

import java.time.LocalDate;
import java.time.Period;
import java.util.List;
import java.util.Map;

@Getter
public class UniversityGraduation extends Credential {
    private final String familyName;
    private final String givenName;
    private final String graduationYear;
    private final String studentId;
    private final String university;
    private final LocalDate issuanceDate;
    private final String expiryDate;
    private final boolean isStudent;

    public UniversityGraduation(Map<String, Object> userDetails, Long credentialId)
    {
        this.familyName = userDetails.get("family_name").toString();
        this.givenName = userDetails.get("given_name").toString();
        this.graduationYear = userDetails.get("graduation_year").toString();
        this.studentId = userDetails.get("student_id").toString();
        this.isStudent = (Boolean) userDetails.get("is_student") == true;
        this.university = userDetails.get("university").toString();
        this.issuanceDate = LocalDate.now();
        this.expiryDate = userDetails.get("expiry_date").toString();
        // DE MODIFICAT
        this.availabilityPeriod = Period.ofYears(200);
        this.vct = "urn:org:certsign:university:graduation:1";
        this.credentialId = credentialId;
    }
}