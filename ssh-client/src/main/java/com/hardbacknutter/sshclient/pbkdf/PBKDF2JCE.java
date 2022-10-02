package com.hardbacknutter.sshclient.pbkdf;

import androidx.annotation.NonNull;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2898">
 * RFC 2898 PKCS #5: Password-Based Cryptography Specification</a>
 * @see <a href="https://docs.oracle.com/en/java/javase/11/docs/specs/security/standard-names.html#secretkeyfactory-algorithms">
 * Standard algorithm names</a>
 */
public class PBKDF2JCE
        implements PBKDF2 {

    @NonNull
    private final String algorithm;

    /**
     * @param algorithm standard JDK name (e.g. "PBKDF2WithHmacSHA1")
     */
    public PBKDF2JCE(@NonNull final String algorithm) {
        this.algorithm = algorithm;
    }

    public PBKDF2JCE(@NonNull final ASN1ObjectIdentifier oid) {
        this.algorithm = getPBEAlgorithm(oid);
    }

    @NonNull
    private String getPBEAlgorithm(@NonNull final ASN1ObjectIdentifier oid) {

        //not exhaustive, but should hopefully do for now.
        // PBKDF2With<prf>

        if (PKCSObjectIdentifiers.id_hmacWithSHA512.equals(oid)) {
            return "PBKDF2WithHmacSHA512";

        } else if (PKCSObjectIdentifiers.id_hmacWithSHA384.equals(oid)) {
            return "PBKDF2WithHmacSHA384";

        } else if (PKCSObjectIdentifiers.id_hmacWithSHA256.equals(oid)) {
            return "PBKDF2WithHmacSHA256";

        } else if (PKCSObjectIdentifiers.id_hmacWithSHA224.equals(oid)) {
            return "PBKDF2WithHmacSHA224";

        } else {
            return "PBKDF2WithHmacSHA1";
        }
    }

    @Override
    @NonNull
    public byte[] generateSecretKey(@NonNull final byte[] passphrase,
                                    @NonNull final byte[] salt,
                                    final int iterations,
                                    final int keyLength)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        final char[] pass = new char[passphrase.length];
        for (int i = 0; i < passphrase.length; i++) {
            pass[i] = (char) (passphrase[i] & 0xff);
        }

        final KeySpec keySpec = new PBEKeySpec(pass, salt, iterations, keyLength * 8);

        final SecretKeyFactory skf = SecretKeyFactory.getInstance(algorithm);
        return skf.generateSecret(keySpec)
                  .getEncoded();
    }
}
