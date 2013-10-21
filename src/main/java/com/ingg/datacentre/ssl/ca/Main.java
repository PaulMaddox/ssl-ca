package com.ingg.datacentre.ssl.ca;

import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.openssl.PEMWriter;

import java.io.FileWriter;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

public class Main {

    private static final Logger log = Logger.getLogger(Main.class.getName());

    private final static String CA_DIRECTORY = "/tmp";
    private final static String CA_CERTIFICATE_FILE = CA_DIRECTORY + "/ca.crt";
    private final static String CA_KEY_FILE = CA_DIRECTORY + "/ca.key";

    public static void main(String[] args) throws Exception {

        String cn = args[0];

        CertificateAuthority ca = new CertificateAuthority();

        // Check to see if there is a valid CA key - or generate one if not
        KeyPair rootKey = CertificateAuthority.loadKeyPairFromFile(CA_KEY_FILE);
        if(rootKey == null){
            System.out.println("Generating & saving new CA key: " + CA_KEY_FILE);
            rootKey = CertificateAuthority.generateKeyPairAndSaveToFile(CA_KEY_FILE);
        } else {
            System.out.println("Loaded CA key from file: " + CA_KEY_FILE);
        }
        ca.setKey(rootKey);

        // ... and the same for a CA certificate
        X509Certificate rootCertificate  = CertificateAuthority.loadCertificateFromFile(CA_CERTIFICATE_FILE);
        if(rootCertificate == null){
            System.out.println("Generating & saving new CA certificate: " + CA_CERTIFICATE_FILE);
            rootCertificate = CertificateAuthority.generateCACertificateAndSaveToFile(CA_CERTIFICATE_FILE, rootKey);
        } else {
            System.out.println("Loaded CA certificate from file: " + CA_CERTIFICATE_FILE);
        }
        System.out.println("CA: " + rootCertificate.getSubjectDN());
        ca.setCertificate(rootCertificate);

        // Now generate the client authentication certificate
        System.out.println("Generating client authentication certificate..." );
        ca.issueCertificate(cn, 365, KeyPurposeId.id_kp_clientAuth);

        // Write out the client certificate with key concatenated below in PEM format
        // ready for Apache SSLProxyMachineCertificateFile entry
        System.out.println("Wrote client certificate & key: /tmp/" + cn + ".crt");
        PEMWriter certWriter = new PEMWriter(new FileWriter("/tmp/" + cn + ".crt"));
        certWriter.writeObject(ca.getIssuedCertificate());
        certWriter.writeObject(ca.getIssuedKeyPair().getPrivate());
        certWriter.close();

    }
}