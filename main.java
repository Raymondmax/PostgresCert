import org.postgresql.ssl.WrappedFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Properties;
import java.security.*;

public class Main {

    public static void main(String[] args) throws GeneralSecurityException {
        String jdbcUrl = "jdbc:postgresql://pgsdev.us.com:9432/postgres";
        String username = "xxx";
        String password = "xxx";


        Properties props = new Properties();
        props.setProperty("user", username);
        props.setProperty("password", password);
        props.setProperty("ssl", "true");
        props.setProperty("sslfactory", DumperFactory.class.getName());

        try {
            Class.forName("org.postgresql.Driver");
            Connection conn = DriverManager.getConnection(jdbcUrl, props);

            long certExpiry = DumperFactory.getCertExpiry();
            System.out.println(certExpiry);

            conn.close(); // Close the connection when done
        } catch (SQLException e) {
            System.err.println("Failed to connect to PostgreSQL server: " + e.getMessage());
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    public static class DumperFactory extends WrappedFactory {
        private static long certExpiry;
        public static Long getCertExpiry(){
            return certExpiry;
        }
        public DumperFactory(String arg) throws GeneralSecurityException {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{new DumperTM()}, null);
            this.factory = ctx.getSocketFactory();
        }

        public static class DumperTM implements X509TrustManager {
            private X509TrustManager getX509TrustManager(TrustManagerFactory trustManagerFactory) throws NoSuchAlgorithmException {
                X509TrustManager defaultTrustManager = null;
                for (TrustManager trustManager : trustManagerFactory.getTrustManagers()) {
                    if (trustManager instanceof X509TrustManager) {
                        defaultTrustManager = (X509TrustManager) trustManager;
                        break;
                    }
                }

                if (defaultTrustManager == null) {
                    throw new NoSuchAlgorithmException("No X509TrustManager found");
                }
                return defaultTrustManager;
            }

            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[0];
            }

            public void checkClientTrusted(X509Certificate[] certs, String authType) throws CertificateException {
                checkServerTrusted(certs, authType);
            }

            public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException {
                try {
                    TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                    trustManagerFactory.init((KeyStore) null);
                    X509TrustManager defaultTrustManager = getX509TrustManager(trustManagerFactory);

                    // Use the defaultTrustManager to validate the server certificate chain
                    defaultTrustManager.checkServerTrusted(certs, authType);
                    for (int i = 0; i < certs.length; ++i) {
                        System.out.println("Cert " + (i + 1) + ":");
                        System.out.println("    Subject: " + certs[i].getSubjectX500Principal().getName());
                        System.out.println("    Issuer: " + certs[i].getIssuerX500Principal().getName());
                        System.out.println("    No After: " + certs[i].getNotAfter().getTime());
                        certExpiry = certs[i].getNotAfter().getTime();
                    }
                } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException e) {
                throw new CertificateException("Error validating server certificate", e);
            }

            }
        }
    }
}
