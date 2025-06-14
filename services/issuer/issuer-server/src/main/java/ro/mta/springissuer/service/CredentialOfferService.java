package ro.mta.springissuer.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class CredentialOfferService {

    private final PreAuthorizedCodeService preAuthorizedCodeService;
    private final QRCodeService qrCodeService;


    public Map<String, Object> createCredentialOfferWithQR(String userId,
                                                           Map<String, Object> userAttributes,
                                                           boolean requirePin) {
        // Get credential offer from authorization server
        Map<String, Object> credentialOffer = preAuthorizedCodeService
                .createPreAuthorizedCode(userId, userAttributes, requirePin);

        // Extract credential offer URL for QR code
        String credentialOfferUrl = (String) credentialOffer.get("credential_offer_url");

        // Generate QR code
        String qrCodeBase64 = qrCodeService.generateQRCodeBase64(credentialOfferUrl, 300, 300);

        // Add QR code to response
        credentialOffer.put("qr_code_base64", qrCodeBase64);
        credentialOffer.put("qr_code_data_url", "data:image/png;base64," + qrCodeBase64);

        return credentialOffer;
    }
}