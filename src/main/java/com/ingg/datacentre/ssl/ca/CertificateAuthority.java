package com.ingg.datacentre.ssl.ca;

import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.openssl.PEMReader;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V1CertificateGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

import javax.security.auth.x500.X500Principal;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.logging.Logger;

/**
 * Generate and sign X509 SSL certificates
 * @author Paul Maddox <paul.maddox@ingg.com>
 */

public class CertificateAuthority {

    private static final Logger log = Logger.getLogger(CertificateAuthority.class.getName());

    private KeyPair caKeyPair;
    private X509Certificate caCertificate;

    private KeyPair issuedKeyPair;
    private X509Certificate issuedCertificate;

    static {
        // Load BouncyCastle security provider
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /**
     * Initiates a new certificate signing authority
     * Attempts to load a CA cert & key from filenames provided otherwise generates new ones
     * @param caCertFile A valid PEM encoded X.509 CA certificate
     * @param caKeyFile A valid PEM encoded RSA private key
     */
    public CertificateAuthority(String caCertFile, String caKeyFile) {

        // Check to see if there is a valid CA key - or generate one if not

        try {
            this.caKeyPair = CertificateAuthority.loadKeyPairFromFile(caKeyFile);
        } catch (IOException e){}

        if(this.caKeyPair == null){
            System.out.println("Generating & saving new CA key: " + caKeyFile);
            try {
                this.caKeyPair = CertificateAuthority.generateKeyPairAndSaveToFile(caKeyFile);
            } catch (Exception e){
                System.out.println("Could not generate new CA key: " + e.getMessage());
                return;
            }
        } else {
            System.out.println("Loaded existing CA key: " + caKeyFile);
        }


        // Check to see if there is a valid CA certificate - or generate one if not
        try {
            this.caCertificate = CertificateAuthority.loadCertificateFromFile(caCertFile);
        } catch (IOException e){}

        if(this.caCertificate == null){
            System.out.println("Generating & saving new CA certificate: " + caCertFile);
            try {
                this.caCertificate = CertificateAuthority.generateCACertificateAndSaveToFile(caCertFile, caKeyPair);
            } catch (Exception e){
                System.out.println("Could not generate new CA certificate: " + e.getMessage());
                return;
            }
        } else {
            System.out.println("Loaded existing CA certificate: " + caCertFile);
        }

        System.out.println("CA: " + caCertificate.getSubjectDN());

    }

    /**
     * Generates an RSA public/private KeyPair
     * @return Generated KeyPair
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    public static KeyPair generateRSAKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
        KeyPairGenerator kpGen = KeyPairGenerator.getInstance("RSA", "BC");
        kpGen.initialize(1024, new SecureRandom());
        return kpGen.generateKeyPair();
    }

    /**
     * Generate an SSL CSR
     * @param pair KeyPair to use for the CSR
     * @param cn Common name for certificate (eg: blah.mydomain.com)
     * @return Generated CSR object
     * @throws Exception
     */
    public static PKCS10CertificationRequest generateCSR(KeyPair pair, String cn) throws Exception {
        return new PKCS10CertificationRequest("SHA256withRSA", new X500Principal(
                "CN=" + cn), pair.getPublic(), null, pair.getPrivate());
    }

    /**
     * Generates a v1 certificate - suitable for a CA with no usage restrictions
     * @param pair A public/private KeyPair to use for signing the CA certificate
     * @return A valid v1 X.509 certificate
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws SignatureException
     * @throws NoSuchAlgorithmException
     * @throws CertificateEncodingException
     */
    public static X509Certificate generateV1Certificate(KeyPair pair)
            throws InvalidKeyException, NoSuchProviderException, SignatureException,
            NoSuchAlgorithmException, CertificateEncodingException {

        X509V1CertificateGenerator certGen = new X509V1CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(new X500Principal("CN=INGG Certificate Authority"));
        certGen.setNotBefore(new Date(System.currentTimeMillis() - 10000));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365 * 50))); // CA valid for 50yrs
        certGen.setSubjectDN(new X500Principal("CN=INGG Certificate Authority"));
        certGen.setPublicKey(pair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        return certGen.generate(pair.getPrivate(), "BC");

    }

    /**
     * Generates an SSL certificate
     * @param cn Common name for certificate (eg: blah.mydomain.com)
     * @param days Number of days the certificate should be valid for
     * @param purposeId A {@link KeyPurposeId} that defines what the certificate can be used for
     * @throws Exception
     */
    public void issueCertificate(String cn, int days, KeyPurposeId purposeId) throws Exception {

        this.issuedKeyPair = generateRSAKeyPair();

        PKCS10CertificationRequest request = generateCSR(issuedKeyPair, cn);

        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();

        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(caCertificate.getSubjectX500Principal());
        certGen.setNotBefore(new Date(System.currentTimeMillis()));
        certGen.setNotAfter(new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * days))); 
        certGen.setSubjectDN(request.getCertificationRequestInfo().getSubject());
        certGen.setPublicKey(request.getPublicKey("BC"));
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");

        certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifierStructure(caCertificate));

        certGen.addExtension(X509Extensions.SubjectKeyIdentifier,

                false, new SubjectKeyIdentifierStructure(request.getPublicKey("BC")));

        certGen.addExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));

        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature
                | KeyUsage.keyEncipherment ));

        certGen.addExtension(X509Extensions.ExtendedKeyUsage, true, new ExtendedKeyUsage(purposeId));

        ASN1Set attributes = request.getCertificationRequestInfo().getAttributes();

        if(attributes != null){
            for (int i = 0; i != attributes.size(); i++) {
                org.bouncycastle.asn1.pkcs.Attribute attr = org.bouncycastle.asn1.pkcs.Attribute.getInstance(attributes.getObjectAt(i));

                if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                    X509Extensions extensions = X509Extensions.getInstance(attr.getAttrValues().getObjectAt(0));

                    Enumeration e = extensions.oids();
                    while (e.hasMoreElements()) {
                        DERObjectIdentifier oid = (DERObjectIdentifier) e.nextElement();
                        X509Extension ext = extensions.getExtension(oid);

                        certGen.addExtension(oid, ext.isCritical(), ext.getValue().getOctets());
                    }
                }
            }
        }

        this.issuedCertificate = certGen.generate(caKeyPair.getPrivate());

    }

    public KeyPair getIssuedKeyPair() {
        return issuedKeyPair;
    }

    public X509Certificate getIssuedCertificate(){
        return issuedCertificate;
    }

    /**
     * Loads an X.509 certificate from file
     * @param filename File to load from
     * @return Valid X509Certificate or null
     * @throws IOException
     */
    public static X509Certificate loadCertificateFromFile(String filename) throws IOException {

        X509Certificate cert = null;

        try {
            final Reader reader = new FileReader(filename);
            final PEMReader pemReader = new PEMReader(reader);

            Object object;
            while ((object = pemReader.readObject()) != null){
                if (object instanceof X509Certificate) {
                    cert = (X509Certificate) object;
                }
            }

            reader.close();
            return cert;
        } catch (FileNotFoundException e){
            return null;
        }

    }

    /**
     * Loads a KeyPair from file
     * @param filename File to load from
     * @return Valid KeyPair or null
     * @throws IOException
     */
    public static KeyPair loadKeyPairFromFile(String filename) throws IOException {

        KeyPair keyPair = null;

        try {

            final Reader reader = new FileReader(filename);
            final PEMReader pemReader = new PEMReader(reader);

            Object object;
            while((object = pemReader.readObject()) != null){
                if(object instanceof KeyPair) {
                    keyPair = (KeyPair) object;
                }
            }

            reader.close();
            return keyPair;

        } catch (FileNotFoundException e){
            return null;
        }

    }

    /**
     * Generates a new RSA KeyPair and saves the private key in PEM format to the specified filename
     * @param filename
     * @return The generated RSA {@link KeyPair}
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    public static KeyPair generateKeyPairAndSaveToFile(String filename) throws NoSuchProviderException, NoSuchAlgorithmException, IOException {

        KeyPair keyPair = generateRSAKeyPair();

        final Writer writer = new FileWriter(filename);
        final PEMWriter pemWriter = new PEMWriter(writer);
        pemWriter.writeObject(keyPair.getPrivate());
        pemWriter.close();

        return keyPair;

    }

    /**
     * Generates a valid CA certificate and saves it in PEM format to the specified filename
     * @param filename The filename to write out a CA certificate in PEM format
     * @param keyPair A private/public {@link KeyPair} to sign the CA certificate with
     * @return The generated certificate
     * @throws NoSuchAlgorithmException
     * @throws CertificateEncodingException
     * @throws NoSuchProviderException
     * @throws InvalidKeyException
     * @throws SignatureException
     * @throws IOException
     */
    public static X509Certificate generateCACertificateAndSaveToFile(String filename, KeyPair keyPair) throws NoSuchAlgorithmException, CertificateEncodingException, NoSuchProviderException, InvalidKeyException, SignatureException, IOException {

        X509Certificate certificate = generateV1Certificate(keyPair);

        final Writer writer = new FileWriter(filename);
        final PEMWriter pemWriter = new PEMWriter(writer);
        pemWriter.writeObject(certificate);
        pemWriter.close();

        return certificate;

    }

}
