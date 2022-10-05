package br.com.becomex.login.java;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse.BodyHandlers;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Scanner;
import java.util.UUID;
import java.util.stream.Collectors;

import com.auth0.jwt.*;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

public class App {
    private static String getTextFromFile(Path path) throws IOException
    {
        var scanner = new Scanner(path.toFile(), StandardCharsets.UTF_8);
        var text = scanner.nextLine();
        scanner.close();
        return text;
    }

    /**
     * Call
     * 
     * ```bash
     * java app \
     * --keystore "path" \
     * --keystore-secret "path" \
     * --key-secret "path" \
     * --client \
     * --key \
     * --api 
     * ```
     * 
     * @param args
     */
    public static void main(String[] args) {
        try {
            AppConfig.loadConfig(args);
            
            var key = loadPEMKey();
            var assertion = generateAssertionToken(key);
            var httpClient = HttpClient.newHttpClient();
            var accessToken = requestAccessToken(httpClient, assertion);
            
            if (AppConfig.ApiUrl != null)
            {
                // Make some API call
                var apiRequest = HttpRequest
                    .newBuilder()
                        .uri(URI.create(AppConfig.ApiUrl))
                        .header("Authorization", "Bearer " + accessToken)
                        .build();

                System.out.println(String.format("Calling HTTP GET %s", AppConfig.ApiUrl));
                var response = httpClient.send(apiRequest, BodyHandlers.ofString());
                System.out.println(response.body());
            }
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
    }

    private static PrivateKey loadPEMKey() throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException, FileNotFoundException, UnrecoverableKeyException {
        // Load PEM/P12 File
        System.out.println("Loading KeyStore (.p12)");
        var keyStore = KeyStore.getInstance(AppConfig.keyStorePath.toFile(),
                getTextFromFile(AppConfig.keyStoreSecretPath).toCharArray());

        System.out.println("Extracting PEM from KeyStore (.p12)");
        var key = keyStore.getKey(AppConfig.keyId,
                getTextFromFile(AppConfig.KeySecretPath).toCharArray());

        if (!(key instanceof PrivateKey))
            throw new IllegalStateException(String.format("Key %s is not a private key 😭.", AppConfig.keyId));
        
        return (PrivateKey) key;
    }
    
    /**
     * Create JWT Assert Token
     * https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
     * client_assertion_type = private_key_jwt
     * 
     * @param key
     * @param secret
     * @return
     */
    private static String generateAssertionToken(PrivateKey key)
    {
        var now = new Date();
        Algorithm algorithm = Algorithm.RSA256(null, (RSAPrivateKey) key); // https://login.becomex.com.br/auth/realms/becomex/.well-known/openid-configuration
        var assertion = JWT.create()
                .withJWTId(UUID.randomUUID().toString()) // REQUIRED. JWT ID. A unique identifier for the token, which can be used to prevent reuse of the token. These tokens MUST only be used once, unless conditions for reuse were negotiated between the parties; any such negotiation is beyond the scope of this specification.
                .withIssuer(AppConfig.clientId) // REQUIRED. Issuer. This MUST contain the client_id of the OAuth Client.
                .withSubject(AppConfig.clientId) // REQUIRED. Subject. This MUST contain the client_id of the OAuth Client.
                .withAudience(AppConfig.isp) // REQUIRED. Audience. The aud (audience) Claim. Value that identifies the Authorization Server as an intended audience. The Authorization Server MUST verify that it is an intended audience for the token. The Audience SHOULD be the URL of the Authorization Server's Token Endpoint.
                .withIssuedAt(now) // OPTIONAL. Time at which the JWT was issued.
                .withExpiresAt(new Date(now.getTime() + 3600 * 1000L)) // REQUIRED. Expiration time on or after which the ID Token MUST NOT be accepted for processing.
                .sign(algorithm);

        System.out.println("== Assertion Token ========================");
        System.out.println(assertion);
        System.out.println("===========================================");

        return assertion;
    }
    
    /**
     * Make an HTTP POST Request to ISP w/ OpenId OAuth2 configuration
     * https://login.becomex.com.br/auth/realms/becomex/protocol/openid-connect/token
     * 
     * client_id = client_identifier
     * grant_type = client_credentials
     * client_assertion_type = urn:ietf:params:oauth:client-assertion-type:jwt-bearer
     * client_assertion = jwt_signed_assertion_token
     * 
     * @param assertion
     * @return
     * @throws InterruptedException
     * @throws IOException
     */
    private static String requestAccessToken(HttpClient httpClient, String assertion) throws IOException, InterruptedException
    {
        var fields = new HashMap<String, String>();
        fields.put("client_id", AppConfig.clientId);
        fields.put("grant_type", "client_credentials");
        fields.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        fields.put("client_assertion", assertion);

        var authRequest = HttpRequest
            .newBuilder()
                .uri(URI.create(String.format("%s/protocol/openid-connect/token", AppConfig.isp)))
                .headers("Content-Type", "application/x-www-form-urlencoded")
                .POST(BodyPublishers.ofString(
                    fields
                        .entrySet()
                        .stream()
                        .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                        .collect(Collectors.joining("&"))))
                    .build();

        var authResponse = httpClient.send(authRequest, BodyHandlers.ofString());
        
        if (authResponse.statusCode() != 200)
            throw new IllegalStateException("Fail to authenticate 🤫");

        var mapper = new ObjectMapper();
        var responseBody = mapper.readValue(authResponse.body(), new TypeReference<HashMap<String, String>>() {});
        var accessToken = responseBody.get("access_token");
        
        System.out.println("== Access Token ===========================");
        System.out.println(accessToken);
        System.out.println("===========================================");

        return accessToken;
    }
}