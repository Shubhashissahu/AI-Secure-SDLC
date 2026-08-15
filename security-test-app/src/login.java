import java.sql.*;
import java.util.Scanner;

/**
 * Deliberately vulnerable login implementation.
 * This file exists ONLY as a test target for security scanners.
 */
public class Login {

    // ⚠️ VULN: Hardcoded database credentials (CWE-798)
    private static final String DB_URL = "jdbc:mysql://localhost:3306/appdb";
    private static final String DB_USER = "root";
    private static final String DB_PASS = "SuperSecret123!";

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASS);
    }

    /**
     * ⚠️ VULN: SQL Injection via string concatenation (CWE-89)
     */
    public static boolean authenticate(String username, String password) {
        try {
            Connection conn = getConnection();
            Statement stmt = conn.createStatement();

            // BAD: Direct string concatenation — classic SQL injection
            String query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";
            ResultSet rs = stmt.executeQuery(query);

            boolean authenticated = rs.next();
            rs.close();
            stmt.close();
            conn.close();
            return authenticated;
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * ⚠️ VULN: Weak hashing algorithm (CWE-916)
     */
    public static String hashPassword(String password) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(password.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return password;
        }
    }

    /**
     * ⚠️ VULN: Command injection (CWE-78)
     */
    public static String runDiagnostic(String host) {
        try {
            Process proc = Runtime.getRuntime().exec("ping -c 1 " + host);
            java.io.InputStream is = proc.getInputStream();
            byte[] output = is.readAllBytes();
            return new String(output);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}
