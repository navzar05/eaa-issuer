package ro.mta.springissuer.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import ro.mta.springissuer.model.request.CredentialRequest;
import ro.mta.springissuer.service.CredentialOfferService;
import ro.mta.springissuer.service.CredentialService;
import ro.mta.springissuer.service.QRCodeService;

import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/issuer-server/wallet")
public class CredentialController {

    private final CredentialService credentialService;
    private final CredentialOfferService credentialOfferService;
    private final QRCodeService qrCodeService;

    private final Set<String> supportedCredentialTypes = Set.of(
            "urn:eu.europa.ec.eudi:pid:1",
            "urn:org:certsign:university:graduation:1"
    );

    public CredentialController(CredentialService credentialService,
                                CredentialOfferService credentialOfferService,
                                QRCodeService qrCodeService) {
        this.credentialService = credentialService;
        this.credentialOfferService = credentialOfferService;
        this.qrCodeService = qrCodeService;
    }

    @PostMapping("/credentialEndpoint")
    public ResponseEntity<?> getCredential(@AuthenticationPrincipal Jwt jwt,
                                           @RequestBody CredentialRequest requestBody) {
        // Validate format is SD-JWT
        if (!"vc+sd-jwt".equals(requestBody.getFormat())) {
            return ResponseEntity.status(400).body(Map.of(
                    "error", "unsupported_format",
                    "error_description", "Only vc+sd-jwt format is supported"
            ));
        }

        // Validate credential type
        if (!supportedCredentialTypes.contains(requestBody.getVct())) {
            return ResponseEntity.status(400).body(Map.of(
                    "error", "unsupported_credential_type",
                    "error_description", "Unsupported credential type: " + requestBody.getVct()
            ));
        }

        try {
            // The credential service now handles different types based on the VCT
            Map<String, Object> sdJwtResponse = credentialService.issueCredential(jwt, requestBody);
            return ResponseEntity.ok(sdJwtResponse);
        } catch (Exception e) {
            return ResponseEntity.status(500).body(Map.of(
                    "error", "issuance_error",
                    "error_description", "Failed to issue credential: " + e.getMessage()
            ));
        }
    }

    @GetMapping("/offer/qr")
    public ResponseEntity<byte[]> generateQRFromParams(
            @RequestParam String userId,
            @RequestParam(defaultValue = "true") boolean requirePin) {

        Map<String, Object> userAttributes = Map.of(
                "name", "Sample User",
                "degree", "Computer Science"
        );

        Map<String, Object> offerData = credentialOfferService.createCredentialOfferWithQR(
                userId, userAttributes, requirePin);

        String credentialOfferUrl = (String) offerData.get("credential_offer_url");
        byte[] qrCodeBytes = qrCodeService.generateQRCodeBytes(credentialOfferUrl, 300, 300);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.IMAGE_PNG);

        return ResponseEntity.ok()
                .headers(headers)
                .body(qrCodeBytes);
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> healthCheck() {
        return ResponseEntity.ok(Map.of("status", "UP"));
    }
}