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
        this.familyName = userDetails.get("lastName").toString();
        this.givenName = userDetails.get("firstName").toString();
        this.graduationYear = userDetails.get("graduationYear").toString();
        this.studentId = userDetails.get("studentId").toString();
        this.isStudent = (Boolean) userDetails.get("student") == true;
        this.university = userDetails.get("university").toString();
        this.issuanceDate = LocalDate.now();
        this.expiryDate = String.valueOf(Period.ofYears(1));
        // DE MODIFICAT
        this.availabilityPeriod = Period.ofYears(1);
        this.vct = "urn:org:certsign:university:graduation:1";
        this.credentialId = credentialId;
    }
}