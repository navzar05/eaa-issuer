package ro.mta.springissuer.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ro.mta.springissuer.service.MetadataService;

import java.util.Map;

@RestController
@RequestMapping(("/issuer-server/.well-known"))
public class MetadataController {

    MetadataService metadataService;

    @Autowired
    MetadataController(MetadataService metadataService) {
        this.metadataService = metadataService;
    }

    @GetMapping("/openid-credential-issuer")
    public Map<String, Object> getCredentialIssuerMetadata(){
        return metadataService.getCredentialIssuerMetadata();
    }
}
