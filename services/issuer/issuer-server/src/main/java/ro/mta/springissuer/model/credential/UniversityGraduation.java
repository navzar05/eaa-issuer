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

    public UniversityGraduation(Map<String, Object> userDetails, String credentialId)
    {
        @SuppressWarnings("unchecked")
        Map<String, List<String>> attributes = (Map<String, List<String>>) userDetails.getOrDefault("attributes", Map.of());
        this.familyName = userDetails.get("lastName").toString();
        this.givenName = userDetails.get("firstName").toString();
        this.graduationYear = attributes.get("graduation_year").toString();
        this.studentId = attributes.get("student_id").toString();
        this.isStudent = attributes.get("is_student").get(0).equals("true");
        this.university = attributes.get("university").toString();
        this.issuanceDate = LocalDate.now();
        this.expiryDate = attributes.get("expiry_date").toString();
        // DE MODIFICAT
        this.availabilityPeriod = Period.ofYears(200);
        this.vct = "urn:org:certsign:university:graduation:1";
        this.credentialId = credentialId;
    }

    public boolean getIsStudent() {
        return isStudent;
    }
}