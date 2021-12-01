package es.fernandoog.cert;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class InstallCertsFromUrl {

    private static final char SEP = File.separatorChar;
    private static final Logger log = LoggerFactory.getLogger(InstallCertsFromUrl.class);
    private static final String JDK = System.getProperty("java.home");
    private static final String LIB = "lib";
    private static final String SECURITY = "security";
    private static final String PATHNAME = JDK + SEP
            + LIB + SEP + SECURITY;
    private static final String KEYSTORE = UUID.randomUUID().toString();
    private static final String[] UNIXCOMAND = {"bash", "-c", "keytool -genkeypair -keystore " + KEYSTORE + "  -dname \"cn=Unknown, ou=Unknown, o=Unknown, c=Unknown\" -storepass " + KEYSTORE + " -keypass " + KEYSTORE + "\""};
    private static final String[] WINCOMAND = {"cmd.exe", "/c", "keytool -genkeypair -keystore " + KEYSTORE + "  -dname \"cn=Unknown, ou=Unknown, o=Unknown, c=Unknown\" -storepass " + KEYSTORE + " -keypass " + KEYSTORE + "\""};
    private static final String TLS = "TLS";
    private static final String SHA_1 = "SHA1";
    private static final String MD_5 = "MD5";

    public static void main(String[] args) {

        SpringApplication.run(InstallCertsFromUrl.class, args);

        process(args);

    }

    private static void process(String[] args) {

        String host;
        int port;
        if ((args.length == 1) || (args.length == 2)) {
            String[] c = args[0].split(":");
            host = c[0];
            port = (c.length == 1) ? 443 : Integer.parseInt(c[1]);
        } else {
            log.error("Usage: java -jar InstallCertsFromUrl <host>[:port]");
            return;
        }

        log.info("JAVA_HOME: {}", JDK);

        ProcessBuilder processBuilder;

        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            processBuilder = new ProcessBuilder(WINCOMAND);
        } else {
            processBuilder = new ProcessBuilder(UNIXCOMAND);
        }


        processBuilder.directory(new File(PATHNAME));
        log.info("Process: {}", processBuilder.command());

        try {
            Process process = processBuilder.start();

            BufferedReader reader =
                    new BufferedReader(new InputStreamReader(process.getInputStream()));

            String line;
            while ((line = reader.readLine()) != null) {
                log.info("Process: {}", line);
            }
            int exitCode = process.waitFor();
            log.info("Exit code: {}", exitCode);

        } catch (IOException | InterruptedException e) {
            log.error("Error: {}", e.getLocalizedMessage());
            Thread.currentThread().interrupt();
        }

        try {
            KeyStore ks;
            try (InputStream in = new FileInputStream(new File(PATHNAME, KEYSTORE))) {
                ks = KeyStore.getInstance(KeyStore.getDefaultType());
                ks.load(in, KEYSTORE.toCharArray());
            }

            SSLContext context = SSLContext.getInstance(TLS);
            TrustManagerFactory tmf =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
            SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
            context.init(null, new TrustManager[]{tm}, null);
            SSLSocketFactory factory = context.getSocketFactory();
            try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
                socket.setSoTimeout(10000);
                socket.startHandshake();
            }

            X509Certificate[] chain = tm.chain;
            if (chain == null) {
                log.error("Could not obtain server certificate chain");
                return;
            }
            log.error("Chain length: {}", tm.chain.length);

            MessageDigest sha1 = MessageDigest.getInstance(SHA_1);
            MessageDigest md5 = MessageDigest.getInstance(MD_5);

            for (int i = 0; i < chain.length; i++) {
                X509Certificate cert = chain[i];
                sha1.update(cert.getEncoded());
                md5.update(cert.getEncoded());
                String alias = host + "-" + (i + 1);
                ks.setCertificateEntry(alias, cert);
                try (OutputStream out = new FileOutputStream(new File(PATHNAME, KEYSTORE))) {
                    ks.store(out, KEYSTORE.toCharArray());
                    log.info("Certificate added: {}", alias);
                }
            }

            log.info("Java keystore create: {}", KEYSTORE);
            log.error("Keystore location: {}", PATHNAME);

        } catch (NoSuchAlgorithmException | KeyStoreException | CertificateException | KeyManagementException | IOException e) {
            log.error("Error: {}", e.getLocalizedMessage());
            log.error("Keystore location: {}", PATHNAME);
        }
    }

    private static class SavingTrustManager implements X509TrustManager {

        private final X509TrustManager tm;
        private X509Certificate[] chain;

        SavingTrustManager(X509TrustManager tm) {
            this.tm = tm;
        }

        public X509Certificate[] getAcceptedIssuers() {
            throw new UnsupportedOperationException();
        }

        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            throw new UnsupportedOperationException();
        }

        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            this.chain = chain;
            tm.checkServerTrusted(chain, authType);
        }
    }
}
