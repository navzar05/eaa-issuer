package ro.mta.springissuer.model.credential;


import lombok.Getter;

import java.time.Period;

@Getter
public class Credential {
    protected Long credentialId;
    protected Period availabilityPeriod;
    protected String vct;
}
