import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.logging.Logger;
import java.util.Scanner;

/**
 * This class contains example methods demonstrating three common security vulnerabilities
 * for educational purposes (Command Injection, Hardcoded Credential, and Log Injection).
 */
public class VulnerableCode {

    // --- VULNERABILITY 2: Hardcoded Sensitive Data (CWE-798) ---
    // Storing a secret key directly in the source code.
    private static final String SECRET_API_KEY = "DEV-API-KEY-4567-VERY-SECRET-1234";

    private static final Logger LOGGER = Logger.getLogger(VulnerableCode.class.getName());

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Demo 1: OS Command Injection
        System.out.println("--- Demo 1: OS Command Injection ---");
        System.out.print("Enter a filename to ping (e.g., localhost or 127.0.0.1): ");
        String userInput = scanner.nextLine();
        executeOsCommand(userInput);

        // Demo 2: Hardcoded Credential Usage
        System.out.println("\n--- Demo 2: Hardcoded Credential Usage ---");
        useHardcodedKey();

        // Demo 3: Log Injection/XSS (via Log)
        System.out.println("\n--- Demo 3: Log Injection Example ---");
        System.out.print("Enter your username for logging purposes: ");
        String username = scanner.nextLine();
        logUserLogin(username);

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
     * If the logging system or display context is a web interface, an attacker could
     * inject malicious characters (like line breaks or script tags) to cause Log Injection
     * or Stored XSS if the log entry is later rendered to a user without encoding.
     * @param username The username entered by the user.
     */
    private static void logUserLogin(String username) {
        // Logging user input directly without sanitization/encoding
        LOGGER.info("User login successful for username: " + username);
        System.out.println("Log entry created.");
    }
}
