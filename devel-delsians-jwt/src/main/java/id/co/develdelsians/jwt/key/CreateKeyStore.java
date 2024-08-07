package id.co.develdelsians.jwt.key;

import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

public class CreateKeyStore {
    public static void main(String[] args) throws Exception {
        // Parameters
        String keystoreFile = "./newKeys/mykeystore.jks";
        String keystorePassword = "delsians456";
        String keyPassword = "devel123";
        String alias = "mykey";

        // Add BouncyCastle Provider
        java.security.Security.addProvider(new BouncyCastleProvider());

        // Create a KeyStore instance with the default type
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, keystorePassword.toCharArray());

        // Generate a key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        // Generate a self-signed certificate
        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + 365 * 86400000L); // Valid for 1 year

        X500Name dnName = new X500Name("CN=RC, OU=jwt-desians, O=devel-delsians, L=Medan, ST=Petisah, C=Indonesia");

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                dnName,
                new java.math.BigInteger(Long.toString(now)),
                startDate,
                endDate,
                dnName,
                keyPair.getPublic()
        );

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(keyPair.getPrivate());

        X509Certificate certificate = new JcaX509CertificateConverter()
                .setProvider("BC")
                .getCertificate(certBuilder.build(contentSigner));

        // Store the key and certificate in the keystore
        keyStore.setKeyEntry(alias, keyPair.getPrivate(), keyPassword.toCharArray(), new Certificate[]{certificate});

        // Save the keystore to a file
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            keyStore.store(fos, keystorePassword.toCharArray());
        }

        System.out.println("Keystore created successfully.");
    }
}
