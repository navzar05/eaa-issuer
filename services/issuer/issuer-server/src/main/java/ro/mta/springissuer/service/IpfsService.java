package ro.mta.springissuer.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.http.MediaType;
import org.springframework.http.client.MultipartBodyBuilder;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;


@Service
public class IpfsService {
    private static final Logger logger = LoggerFactory.getLogger(IpfsService.class);

    @Value("${path.to.cascade.executable}")
    private String executablePath;

    @Value("${path.to.revocation.list}")
    public String credentialStatusFile;

    @Value("${pinata.api.key}")
    private String pinataApiKey;

    @Value("${pinata.api.secret}")
    private String pinataApiSecret;

    @Value("${path.to.latest.ipfs.cid.file}")
    private String lastIpfsHashFile;

    private String lastIpfsHash;

    public static final String outputPath = "cascade.bin";

    private final WebClient webClient = WebClient.builder()
            .baseUrl("https://api.pinata.cloud")
            .build();

    @PostConstruct
    void init() throws IOException {

        if (Path.of(lastIpfsHashFile).toFile().exists())
            lastIpfsHash = Files.readString(Path.of(lastIpfsHashFile));
        else
            sendCascadeToIpfs();
    }

    @Scheduled(cron = "0 0 0 * * *")
    public void sendCascadeToIpfs() throws IOException {

        buildCascade();

        File file = new File("cascade.bin");
        if (!file.exists()) throw new RuntimeException("File not found: cascade.bin");

        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        String cascadeFileName = "cascade_" + timestamp + ".bin";

        FileSystemResource resource = new FileSystemResource(file);

        MultipartBodyBuilder builder = new MultipartBodyBuilder();
        builder.part("file", resource)
                .header("Content-Disposition", "form-data; name=file; filename=" + cascadeFileName);

        webClient.post()
                .uri("/pinning/pinFileToIPFS")
                .header("pinata_api_key", pinataApiKey)
                .header("pinata_secret_api_key", pinataApiSecret)
                .contentType(MediaType.MULTIPART_FORM_DATA)
                .body(BodyInserters.fromMultipartData(builder.build()))
                .retrieve()
                .bodyToMono(String.class)
                .map(response -> {
                    try {
                        JsonNode json = new ObjectMapper().readTree(response);
                        lastIpfsHash = json.get("IpfsHash").asText();
                        logger.info("Uploaded to IPFS: {}", lastIpfsHash);
                        return lastIpfsHash;
                    } catch (Exception e) {
                        throw new RuntimeException("Invalid response from Pinata", e);
                    }
                })
                .block();

        Files.writeString(Paths.get(lastIpfsHashFile), lastIpfsHash);

        logger.info("IPFS hash saved to {}", lastIpfsHashFile);

    }

    private void buildCascade() throws IOException {
        List<String> command = new ArrayList<>();
        command.add(executablePath);
        command.add("build");
        command.add("--status_list");
        command.add(credentialStatusFile);
        command.add("--output");
        command.add(outputPath);

        ProcessBuilder processBuilder = new ProcessBuilder(command);
        Process process = processBuilder.start();

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
             BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {

            String line;
            while ((line = reader.readLine()) != null) {
                logger.info("[cascade stdout] {}", line);
            }
            while ((line = errorReader.readLine()) != null) {
                logger.error("[cascade stderr] {}", line);
            }

            boolean completed = process.waitFor(5, TimeUnit.MINUTES);
            if (!completed) {
                process.destroyForcibly();
                throw new IOException("Cascade build process timed out");
            }

            if (process.exitValue() != 0) {
                throw new IOException("Cascade build process failed with exit code " + process.exitValue());
            }

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Cascade build process was interrupted", e);
        }
    }

    public String getLastIpfsHash() {
        return lastIpfsHash;
    }

}