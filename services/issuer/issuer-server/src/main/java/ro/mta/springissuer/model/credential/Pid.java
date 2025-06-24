package ro.mta.springissuer.model.credential;

import lombok.Getter;

import java.time.LocalDate;
import java.time.Period;
import java.time.Year;
import java.util.List;
import java.util.Map;

@Getter
public class Pid extends Credential {
    private final String familyName;
    private final String givenName;
    private final LocalDate birthDate;
    private final String birthPlace;
    private final List<String> nationalities;
    private final String residentCountry;
    private final Boolean isOver18;
    private final Integer ageInYears;
    private final Year ageBirthYear;


    public Pid(Map<String, Object> userDetails, Long credentialId)
    {
        @SuppressWarnings("unchecked")
        Map<String, List<String>> attributes = (Map<String, List<String>>) userDetails.getOrDefault("attributes", Map.of());

        this.familyName = userDetails.get("lastName").toString();
        this.givenName = userDetails.get("firstName").toString();
        this.birthDate = LocalDate.parse(attributes.get("birthdate").get(0));
        this.birthPlace = "Unknown";
        this.nationalities = List.of("RO");
        this.residentCountry = "RO";
        if (attributes.get("is_over_18") != null)
            this.isOver18 = attributes.get("is_over_18").get(0).equals("true");
        else
            this.isOver18 = false;

        if (attributes.get("age_in_years") != null)
            this.ageInYears = Integer.parseInt(attributes.get("age_in_years").get(0));
        else
            this.ageInYears = 18;
        this.ageBirthYear = Year.of(birthDate.getYear());

        this.availabilityPeriod = Period.ofYears(10);
        this.vct = "urn:eu.europa.ec.eudi:pid:1";
        this.credentialId = credentialId;
    }
}