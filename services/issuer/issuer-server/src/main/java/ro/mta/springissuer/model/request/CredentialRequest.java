package ro.mta.springissuer.model.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class CredentialRequest {

    @JsonProperty("format")
    private String format;

    @JsonProperty("vct")
    private String vct;


}

