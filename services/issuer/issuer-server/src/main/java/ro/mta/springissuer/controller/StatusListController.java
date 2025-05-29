package ro.mta.springissuer.controller;

import com.nimbusds.jose.util.Resource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import ro.mta.springissuer.service.CredentialService;
import ro.mta.springissuer.service.IpfsService;
import ro.mta.springissuer.service.StatusListService;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;

@RestController
public class StatusListController {

    private static final Logger logger = LoggerFactory.getLogger(StatusListController.class);

    private StatusListService statusListService;

    private IpfsService ipfsService;

    StatusListController(StatusListService statusListService, IpfsService ipfsService) {
        this.statusListService = statusListService;
        this.ipfsService = ipfsService;
    }

    @GetMapping("/revocation-list")
    public ResponseEntity<Map<String, String>> getStatusList() {
        try {
            String content = Files.readString(Paths.get(statusListService.getStatusListPath()));
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
