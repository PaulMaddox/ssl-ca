package com.ingg.datacentre.ssl.ca;

import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.openssl.PEMWriter;

import java.io.FileWriter;
import java.util.logging.Logger;

public class Main {

    private static final Logger log = Logger.getLogger(Main.class.getName());

    private final static String CA_DIRECTORY = "/tmp";
    private final static String CA_CERTIFICATE_FILE = CA_DIRECTORY + "/ca.crt";
    private final static String CA_KEY_FILE = CA_DIRECTORY + "/ca.key";

    public static void main(String[] args) throws Exception {

        if(args.length != 2){
            showUsage();
            return;
        }

        String purpose = args[0];
        String cn = args[1];

        CertificateAuthority ca = new CertificateAuthority(CA_CERTIFICATE_FILE, CA_KEY_FILE);

        // Now generate the certificate
        if(purpose.equals("server")){

            System.out.println("Generating server authentication certificate..." );
            ca.issueCertificate(cn, 365, KeyPurposeId.id_kp_serverAuth);

            // Write out separate key & certificate for server certs
            System.out.println("Wrote server certificate: /tmp/" + cn + ".crt");
            PEMWriter certWriter = new PEMWriter(new FileWriter("/tmp/" + cn + ".crt"));
            certWriter.writeObject(ca.getIssuedCertificate());
            certWriter.close();

            System.out.println("Wrote server certificate key: /tmp/" + cn + ".key");
            PEMWriter keyWriter = new PEMWriter(new FileWriter("/tmp/" + cn + ".key"));
            keyWriter.writeObject(ca.getIssuedKeyPair().getPrivate());
            keyWriter.close();

        } else {

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

    private static void showUsage() {
        System.out.println("Usage:");
        System.out.println("java -jar ingg-ssl-ca.jar <client|server> <common name>");
    }
}