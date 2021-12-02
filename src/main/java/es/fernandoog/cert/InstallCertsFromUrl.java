package es.fernandoog.cert;

import javax.net.ssl.*;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class InstallCertsFromUrl {

    private static final Logger log = LoggerFactory.getLogger(InstallCertsFromUrl.class);

    public static final String DEFAULTPASSWORD = "changeit";
    public static final String JAVAPATH = System.getProperty("java.home") + File.separatorChar
            + "lib" + File.separatorChar + "security";
    public static final String JSSECACERTS = "jssecacerts";
    public static final String CACERTS = "cacerts";
    public static final String TLS = "TLS";
    public static final String SHA_1 = "SHA1";
    public static final String MD_5 = "MD5";

    public static void main(String[] args) {

        SpringApplication.run(InstallCertsFromUrl.class, args);

        process(args);

    }

    private static void process(String[] args) {

        String host;
        int port;
        char[] passphrase;
        if ((args.length == 1) || (args.length == 2)) {
            String[] c = args[0].split(":");
            host = c[0];
            port = (c.length == 1) ? 443 : Integer.parseInt(c[1]);
            String p = (args.length == 1) ? DEFAULTPASSWORD : args[1];
            passphrase = p.toCharArray();
        } else {
            log.info("Usage: java InstallCert <host>[:port]");
            return;
        }


        try {
            KeyStore ks;
            try (InputStream in = new FileInputStream(getKeyStoreFile())) {
                ks = KeyStore.getInstance(KeyStore.getDefaultType());
                ks.load(in, passphrase);
            }

            SSLContext context = SSLContext.getInstance(TLS);
            TrustManagerFactory tmf =
                    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
            SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
            context.init(null, new TrustManager[]{tm}, null);
            SSLSocketFactory factory = context.getSocketFactory();

            log.info("Opening connection to {}", host);

            try (SSLSocket socket = (SSLSocket) factory.createSocket(host, port)) {
                socket.setSoTimeout(10000);
                log.info("Starting SSL handshake...");
                socket.startHandshake();
                log.info("No errors, certificate is already trusted");
            } catch (SSLException e) {
                log.info(e.getLocalizedMessage());
            }

            X509Certificate[] chain = tm.chain;
            if (chain == null) {
                log.info("Could not obtain server certificate chain");
                return;
            }

            log.info("Number of certificates {}", chain.length);

            MessageDigest sha1 = MessageDigest.getInstance(SHA_1);
            MessageDigest md5 = MessageDigest.getInstance(MD_5);

            for (int i = 0; i < chain.length; i++) {
                X509Certificate cert = chain[i];
                sha1.update(cert.getEncoded());
                md5.update(cert.getEncoded());
                String alias = host + "-" + (i + 1);
                ks.setCertificateEntry(alias, cert);
                try (OutputStream out = new FileOutputStream(getKeyStoreFile())) {
                    ks.store(out, passphrase);
                }
                log.info("Add certificate {}", cert.getSubjectDN());
            }
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException | KeyManagementException e) {
            log.error(e.getLocalizedMessage());
            log.info("Usage: java InstallCert <host>[:port]");
        }
    }

    private static File getKeyStoreFile() {
        File file = new File(JSSECACERTS);
        if (!file.isFile()) {
            File dir = new File(JAVAPATH);
            file = new File(dir, JSSECACERTS);
            if (!file.isFile()) {
                file = new File(dir, CACERTS);
            }
        }
        return file;
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