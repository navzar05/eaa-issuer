package ro.mta.springissuer.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import ro.mta.springissuer.service.IpfsService;
import ro.mta.springissuer.service.RevocationListService;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;

@RestController
public class RevocationListController {

    private static final Logger logger = LoggerFactory.getLogger(RevocationListController.class);

    private RevocationListService revocationListService;

    private IpfsService ipfsService;

    RevocationListController(RevocationListService revocationListService, IpfsService ipfsService) {
        this.revocationListService = revocationListService;
        this.ipfsService = ipfsService;
    }

    @GetMapping("/revocation-list")
    public ResponseEntity<Map<String, String>> getStatusList() {
        try {
            String content = Files.readString(Paths.get(revocationListService.getStatusListPath()));
            Map<String, String> response = Map.of("jwt", content);
            return ResponseEntity.status(HttpStatus.OK).body(response);
        } catch (IOException e) {
            logger.error("Error reading status list file: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/revocation-list-ipfs")
    public ResponseEntity<Void> getStatusListIpfs() {
        try {
            String baseUri = "https://gateway.pinata.cloud/ipfs/";
            String cid = ipfsService.getLastIpfsHash();
            String fullUrl = baseUri + cid;

            HttpHeaders headers = new HttpHeaders();
            headers.setLocation(URI.create(fullUrl));

            return new ResponseEntity<>(headers, HttpStatus.FOUND);
        } catch (Exception e) {
            logger.error("Error fetching status list from IPFS: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

}
