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
    private final String residentAddress;
    private final String residentCountry;
    private final String residentState;
    private final String residentCity;
    private final String residentPostalCode;
    private final String residentStreet;
    private final String residentHouseNumber;
    private final byte[] portrait;
    private final String familyNameBirth;
    private final String givenNameBirth;
    private final Integer sex;
    private final String emailAddress;
    private final String mobilePhoneNumber;
    private final Boolean isOver18;
    private final Integer ageInYears;
    private final Year ageBirthYear;


    public Pid(Map<String, Object> userDetails, String credentialId)
    {
        @SuppressWarnings("unchecked")
        Map<String, List<String>> attributes = (Map<String, List<String>>) userDetails.getOrDefault("attributes", Map.of());

        this.familyName = userDetails.get("lastName").toString();
        this.givenName = userDetails.get("firstName").toString();
        this.birthDate = LocalDate.parse(attributes.get("birthdate").get(0));
        this.birthPlace = "Unknown";
        this.nationalities = List.of("RO");
        this.residentAddress = null;
        this.residentCountry = "RO";
        this.residentState = null;
        this.residentCity = null;
        this.residentPostalCode = null;
        this.residentStreet = null;
        this.residentHouseNumber = null;
        this.portrait = null;
        this.familyNameBirth = null;
        this.givenNameBirth = null;
        this.sex = null;
        this.emailAddress = null;
        this.mobilePhoneNumber = null;
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