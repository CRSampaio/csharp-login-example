package br.com.becomex.login.java;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;

public class AppConfig {
    public static String clientId = null;
    public static String isp = "https://login.becomex.com.br/auth/realms/becomex";
    public static String keyId = null;
    public static String ApiUrl = null;
    public static Path keyStorePath = null;
    public static Path keyStoreSecretPath = null;
    public static Path KeySecretPath = null;

    private static BufferedReader input = new BufferedReader(new InputStreamReader(System.in));

    public static void loadConfig(String[] args) throws IOException {
        System.out.println("Starting config validation.");

        extractConfigFromArguments(args);
        assertClientIdConfig();
        assertKeyStorePathConfig();
        assertKeyStoreSecretFileConfig();
        assertKeyIdConfig();
        assertPEMSecretFileConfig();
        assertApiUrlConfig();
    }
    
    private static void assertApiUrlConfig() throws IOException {
        if (ApiUrl == null)
        {
            System.out.println("Do you want to check access_token w/ a GET connection?");
            System.out.println("Api URL:");
            AppConfig.ApiUrl = sanitizeValue(input.readLine());
        }
    }

    private static void assertPEMSecretFileConfig() throws IOException {
        while (KeySecretPath == null)
        {
            System.out.println("Private Key Secret file was not provided.");
            System.out.println("PEM secret path:");
            AppConfig.KeySecretPath = sanitizePath(input.readLine());
        }
    }

    private static void assertKeyStoreSecretFileConfig() throws IOException {
        while (keyStoreSecretPath == null)
        {
            System.out.println("Keystore Secret File was not provided.");
            System.out.println("KeyStore's secret path:");
            AppConfig.keyStoreSecretPath = sanitizePath(input.readLine());
        }
    }

    private static void assertKeyStorePathConfig() throws IOException {
        while (keyStorePath == null)
        {
            System.out.println("Keystore file was not provided.");
            System.out.println("KeyStore path:");
            AppConfig.keyStorePath = sanitizePath(input.readLine());
        }
    }

    private static void assertClientIdConfig() throws IOException {
        while (clientId == null) {
            System.out.println("Client Id not found. Inform the application identifier provided by Becomex.");
            System.out.println("Client Id:");
            AppConfig.clientId = sanitizeValue(input.readLine());
        }
    }
    
    private static void assertKeyIdConfig() throws IOException {
        while (keyId == null) {
            System.out.println("KeyId not found. Inform the name of key inside KeyStore.");
            System.out.println("Key Id:");
            AppConfig.keyId = sanitizeValue(input.readLine());
        }
    }

    private static void extractConfigFromArguments(String[] args) {
        for (var i = 0; i < (args.length - 1); i += 2) {
            switch (args[i].toLowerCase()) {
                case "--keystore":
                    keyStorePath = sanitizePath(args[i + 1]);
                    break;

                case "--keystore-secret":
                    keyStoreSecretPath = sanitizePath(args[i + 1]);
                    break;

                case "--key-secret":
                    KeySecretPath = sanitizePath(args[i + 1]);
                    break;

                case "--client":
                    clientId = sanitizeValue(args[i + 1]);
                    break;

                case "--key":
                    keyId = sanitizeValue(args[i + 1]);
                    break;

                case "--api":
                    ApiUrl = sanitizeValue(args[i + 1]);
                    break;
            }
        }
    }
    
    private static String sanitizeValue(String value)
    {
        if (value == null)
            return value;

        if (value.startsWith("--"))
            return null;

        value = value.trim();

        if (value.isEmpty())
            return null;

        return value;
    }
    
    private static Path sanitizePath(String value)
    {
        var pathStr = sanitizeValue(value);
        
        if (pathStr == null)
            return null;

        var path = Path.of(pathStr.replaceAll("\"", ""));
        
        if (!Files.exists(path))
            return null;
        
        return path;
    }
}
