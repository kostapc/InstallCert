/**
 * Copyright 2006 Sun Microsystems, Inc.  All Rights Reserved.
 * Originally posted at: (not available now)
 * http://blogs.sun.com/andreas/resource/InstallCert.java
 * this version:
 * http://code.naishe.in/2011/07/looks-like-article-no-more-unable-to.html
 * Use:
 * java InstallCert hostname
 * Example:
 * % java InstallCert ecc.fedora.redhat.com
 */

import javax.net.ssl.*;
import java.io.*;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.prefs.Preferences;

/**
 * Class used to add the server's certificate to the KeyStore
 * with your trusted certificates.
 */
public class InstallCert {

    private static final String DEFAULT_PASSPHRASE = "changeit";

    public static void main(String[] argc) {
        if(!isAdmin()) {
            System.out.println("you need admin/root access to modify keystore");
            return;
        }
        if (argc.length == 0) {
            System.out.println("USAGE: java InstallCert <valid URI> [keystore-passphrase]");
        }
        try {
            for (int i = 0; i < argc.length; i++) {
                System.out.println("[" + i + "] " + argc[i]);
            }
            if (argc.length > 1) {
                install(argc[0], argc[1]);
            } else {
                install(argc[0]);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void install(String urlString) throws Exception {
        install(urlString, DEFAULT_PASSPHRASE);
    }

    public static void install(String urlString, String passString) throws Exception {
        URL url = new URL(urlString);
        String host = url.getHost();
        int port = url.getPort();
        if (port < 0) {
            port = url.getDefaultPort();
        }
        char[] passphrase = passString.toCharArray();
        File dir = new File(
                System.getProperty("java.home") + File.separatorChar
                        + "lib" + File.separatorChar + "security");
        File file = new File(dir, "cacerts");

        System.out.println("Loading KeyStore " + file + "...");
        InputStream in = new FileInputStream(file);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(in, passphrase);
        in.close();

        SSLContext context = SSLContext.getInstance("TLS");
        TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory
                        .getDefaultAlgorithm());
        tmf.init(ks);
        X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
        SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
        context.init(null, new TrustManager[]{tm}, null);
        SSLSocketFactory factory = context.getSocketFactory();

        System.out.println("Opening connection to " + host + ":" + port + "...");
        final SSLSocket socket = (SSLSocket) factory.createSocket(host, port);
        socket.setSoTimeout(10000);
        try {
            System.out.println("Starting SSL handshake...");
            socket.startHandshake();
            socket.close();
            System.out.println();
            System.out.println("No errors, certificate is already trusted");
            return;
        } catch (final SSLException e) {
            System.out.println("SSL error, installing certificate: " + e.getMessage());
            //e.printStackTrace(System.out);
        }

        X509Certificate[] chain = tm.chain;
        if (chain == null) {
            System.out.println("Could not obtain server certificate chain");
            return;
        }

        System.out.println();
        System.out.println("Server sent " + chain.length + " certificate(s):");
        System.out.println();
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        for (int i = 0; i < chain.length; i++) {
            X509Certificate cert = chain[i];
            System.out.println
                    (" " + (i + 1) + " Subject " + cert.getSubjectDN());
            System.out.println("   Issuer  " + cert.getIssuerDN());
            sha1.update(cert.getEncoded());
            System.out.println("   sha1    " + toHexString(sha1.digest()));
            md5.update(cert.getEncoded());
            System.out.println("   md5     " + toHexString(md5.digest()));
            System.out.println();
        }

        //System.out.println("Enter certificate to add to trusted keystore or 'q' to quit: [1]");
        //String line = reader.readLine().trim();
        int k = 1; // getting first - just for specified host
        /*try {
            k = (line.length() == 0) ? 0 : Integer.parseInt(line) - 1;
        } catch (NumberFormatException e) {
            System.out.println("KeyStore not changed");
            return;
        }*/

        X509Certificate cert = chain[k];
        String alias = host + "-" + (k + 1);
        ks.setCertificateEntry(alias, cert);

        OutputStream out = new FileOutputStream(file.getAbsolutePath());
        ks.store(out, passphrase);
        out.close();

        System.out.println();
        System.out.println(cert);
        System.out.println();
        System.out.println(
                "Added certificate to keystore '" + file.getAbsolutePath() + "' using alias '" + alias + "'"
        );

        System.out.println("revalidate url with plain URLConnection...");
        URLConnection connection = url.openConnection();
        connection.connect();
        int contentLength = connection.getContentLength();
        System.out.println("content length for " + url + " : " + contentLength);
        System.out.println("ALL DONE!");
    }

    private static final char[] HEXDIGITS = "0123456789abcdef".toCharArray();

    private static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int b : bytes) {
            b &= 0xff;
            sb.append(HEXDIGITS[b >> 4]);
            sb.append(HEXDIGITS[b & 15]);
            sb.append(' ');
        }
        return sb.toString();
    }

    // http://stackoverflow.com/questions/4350356/detect-if-java-application-was-run-as-a-windows-admin
    public static boolean isAdmin() {
        Preferences prefs = Preferences.systemRoot();
        synchronized (System.err) {    // better synchroize to avoid problems with other threads that access System.err
            System.setErr(null);
            try {
                String key = "test_access_"+System.currentTimeMillis();
                prefs.put(key, "foobar"); // SecurityException on Windows
                prefs.remove(key);
                prefs.flush(); // BackingStoreException on Linux
                return true;
            } catch (Exception e) {
                return false;
            } finally {
                System.setErr(System.err);
            }
        }
    }

    private static class SavingTrustManager implements X509TrustManager {

        private final X509TrustManager tm;
        private X509Certificate[] chain;

        SavingTrustManager(final X509TrustManager tm) {
            this.tm = tm;
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            /**
             * This change has been done due to the following resolution advised for Java 1.7+
             http://infposs.blogspot.kr/2013/06/installcert-and-java-7.html
             **/
            return new X509Certificate[0];
            // throw new UnsupportedOperationException();
        }

        @Override
        public void checkClientTrusted(final X509Certificate[] chain, final String authType)
                throws CertificateException
        {
            throw new UnsupportedOperationException();
        }

        @Override
        public void checkServerTrusted(final X509Certificate[] chain, final String authType)
                throws CertificateException
        {
            this.chain = chain;
            this.tm.checkServerTrusted(chain, authType);
        }
    }

}