package ro.mta.springissuer.model.credential;


import lombok.Getter;

import java.time.Period;

@Getter
public abstract class Credential {
    protected String credentialId;
    protected Period availabilityPeriod;
    protected String vct;
}
