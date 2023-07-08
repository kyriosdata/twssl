package br.ufg.twssl.util;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class TrustStoreUtil {

    public static void reloadTrustStore(final KeyStore trustStore) throws IOException, CertificateException, NoSuchAlgorithmException, KeyStoreException, KeyManagementException {
        // Reload the truststore to update the JVM's trust manager
        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);

        // Get the default SSLContext and update it with the new trust manager
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustManagerFactory.getTrustManagers(), null);

        // Update the default SSLContext with the new trust manager
        SSLContext.setDefault(sslContext);
    }
    public static KeyStore addCertificateTruststore(final X509Certificate[] clientCertificates,final String truststorePath, final String truststorePassword) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        // Load the default truststore
        KeyStore truststore = KeyStore.getInstance(KeyStore.getDefaultType());
        FileInputStream fis = new FileInputStream(truststorePath);
        truststore.load(fis, truststorePassword.toCharArray());

        //Set new certificate into truststore
        X509Certificate certificate = clientCertificates[0];
        truststore.setCertificateEntry(certificate.getSubjectX500Principal().getName(), certificate);
        System.out.println(truststore.getCertificateAlias(certificate));

        return truststore;
    }

    public static boolean isCertificateInTruststore(String certificateAlias, String truststorePath, String truststorePassword) throws Exception {
        // Load the truststore
        KeyStore truststore = KeyStore.getInstance(KeyStore.getDefaultType());
        try (FileInputStream fis = new FileInputStream(truststorePath)) {
            truststore.load(fis, truststorePassword.toCharArray());
        }
        // Check if the certificate is in the truststore
        return truststore.containsAlias(certificateAlias);
    }
}
