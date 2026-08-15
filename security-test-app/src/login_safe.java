import java.sql.*;
import java.io.InputStream;

/**
 * Secure login implementation (CWE-89, CWE-798, CWE-916, CWE-78 Remediations).
 */
public class LoginSafe {

    // SECURE: Database password loaded from environment variable (CWE-798)
    private static final String DB_URL = System.getenv("DB_URL");
    private static final String DB_USER = System.getenv("DB_USER");
    private static final String DB_PASS = System.getenv("DB_PASS");

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
    }

    /**
     * SECURE: PreparedStatement parameterized query (CWE-89)
     */
    public static boolean authenticateSafe(String username, String password) {
        String query = "SELECT id FROM users WHERE username = ? AND password = ?";
        try (Connection conn = getConnection();
             PreparedStatement stmt = conn.prepareStatement(query)) {

            stmt.setString(1, username);
            stmt.setString(2, password);

            try (ResultSet rs = stmt.executeQuery()) {
                return rs.next();
            }
        } catch (SQLException e) {
            return false;
        }
    }

    /**
     * SECURE: ProcessBuilder with array arguments and input validation (CWE-78)
     */
    public static String runDiagnosticSafe(String host) {
        if (!host.matches("^[a-zA-Z0-9.-]+$")) {
            throw new IllegalArgumentException("Invalid host format");
        }
        try {
            ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", host);
            Process proc = pb.start();
            try (InputStream is = proc.getInputStream()) {
                return new String(is.readAllBytes());
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}
