import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.logging.Logger;
import java.util.Scanner;
import java.security.MessageDigest; // Needed for hashing
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets; // Needed for hashing

/**
 * This class contains example methods demonstrating three common security vulnerabilities
 * and one security hotspot for educational purposes.
 */
public class VulnerableCode {

    // --- VULNERABILITY 2: Hardcoded Sensitive Data (CWE-798) ---
    // Storing a secret key directly in the source code.
    private static final String SECRET_API_KEY = "DEV-API-KEY-4567-VERY-SECRET-1234";

    private static final Logger LOGGER = Logger.getLogger(VulnerableCode.class.getName());

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Demo 1: OS Command Injection
        System.out.println("--- Demo 1: OS Command Injection (CWE-78) ---");
        System.out.print("Enter a filename to ping (e.g., localhost or 127.0.0.1): ");
        String userInput = scanner.nextLine();
        executeOsCommand(userInput);

        // Demo 2: Hardcoded Credential Usage
        System.out.println("\n--- Demo 2: Hardcoded Credential Usage (CWE-798) ---");
        useHardcodedKey();

        // Demo 3: Log Injection/XSS (via Log)
        System.out.println("\n--- Demo 3: Log Injection Example (CWE-117) ---");
        System.out.print("Enter your username for logging purposes: ");
        String username = scanner.nextLine();
        logUserLogin(username);

        // Demo 4: Security Hotspot (Weak Cryptographic Hash)
        System.out.println("\n--- Demo 4: Security Hotspot (Weak MD5 Hash) ---");
        useWeakHashing();

        scanner.close();
    }

    /**
     * VULNERABILITY 1: Executes an OS command based on unsanitized user input.
     * An attacker could inject malicious commands here (e.g., '127.0.0.1; ls /').
     * @param target The user-provided string used as part of the command.
     */
    private static void executeOsCommand(String target) {
        String osName = System.getProperty("os.name").toLowerCase();
        String command;

        if (osName.contains("win")) {
            // Windows command structure
            command = "ping -n 1 " + target;
        } else {
            // Unix/Linux command structure
            command = "ping -c 1 " + target;
        }

        LOGGER.info("Executing command: " + command);

        try {
            // Execute the command directly with user input appended
            Process process = Runtime.getRuntime().exec(command);

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }

            process.waitFor();
            if (process.exitValue() != 0) {
                 System.err.println("Command failed with exit code: " + process.exitValue());
            }

        } catch (Exception e) {
            System.err.println("An error occurred during command execution: " + e.getMessage());
        }
    }

    /**
     * VULNERABILITY 2: Simulates the usage of a hardcoded sensitive key.
     * The key is directly available in the compiled code.
     */
    private static void useHardcodedKey() {
        System.out.println("Connecting to external service using hardcoded key...");
        // In a real application, this key would be used to authenticate with an external API
        if (SECRET_API_KEY.startsWith("DEV-")) {
            System.out.println("Authentication successful (using development key).");
            // Do sensitive operation...
        } else {
            System.out.println("Authentication failed.");
        }
    }

    /**
     * VULNERABILITY 3: Logs unsanitized user input directly.
     * An attacker could inject malicious characters (like line breaks) to forge log entries.
     * @param username The username entered by the user.
     */
    private static void logUserLogin(String username) {
        // Logging user input directly without sanitization/encoding
        LOGGER.info("User login successful for username: " + username);
        System.out.println("Log entry created.");
    }

    /**
     * HOTSPOT 4: Uses a weak or broken cryptographic hash (MD5).
     * MD5 is no longer considered secure for cryptographic purposes like integrity checking
     * or password hashing due to known collision attacks. This is often flagged as a
     * security hotspot, recommending review and migration to SHA-256 or SHA-3.
     */
    private static void useWeakHashing() {
        String data = "SensitiveDataToHash123";
        try {
            // Hotspot: Using MD5, which is a known weak algorithm
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(data.getBytes(StandardCharsets.UTF_8));

            // Convert byte array to hex string for display
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            System.out.println("Data: '" + data + "'");
            System.out.println("MD5 Hash: " + hexString.toString());

        } catch (NoSuchAlgorithmException e) {
            System.err.println("MD5 algorithm not found. (This is fine, but the intent was to use it.)");
        }
    }
}
