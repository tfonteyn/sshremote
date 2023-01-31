package com.hardbacknutter.sshclient.keypair.decryptors;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.ciphers.SshCipher;
import com.hardbacknutter.sshclient.keypair.pbkdf.PBKDFJCE;
import com.hardbacknutter.sshclient.keypair.pbkdf.PBKDFSCrypt;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;

public class DecryptPKCS8 implements PKDecryptor {

    @NonNull
    private final SshClientConfig config;

    public DecryptPKCS8(@NonNull final SshClientConfig config) {
        this.config = config;
    }

    @Override
    public void setCipher(@NonNull final SshCipher cipher,
                          @NonNull final byte[] cipherIV) {
    }

    @Override
    @NonNull
    public byte[] decrypt(@NonNull final byte[] passphrase,
                          @NonNull final byte[] blob)
            throws GeneralSecurityException, IOException {

        // RSA encrypted with prvKeyAlgOID == id_PBES2
        // Sequence                                                     ==> 'root'
        //     Sequence                                                 ==> 'algorithmHeaderSeq'
        //         ObjectIdentifier(1.2.840.113549.1.5.13)              ==> 'prvKeyAlgOID'
        //         Sequence                                             ==> 'attributeHeaderSeq'
        //             Sequence                                         ==> 'paramHeaderSeq'
        // --- PKCS5 params -------------------------------------------------------------------
        //                 ObjectIdentifier(1.2.840.113549.1.5.12)      ==> 'paramOID'
        //                 Sequence                                     ==> 'parameters'
        //                     DER Octet String[8]                      ==> 'salt'
        //                         29a1b47e62a1997c
        //                     Integer(2048)                            ==> 'iterations'
        //                     Sequence                                 ==> 'yaSeq'
        //                         ObjectIdentifier(1.2.840.113549.2.9) ==> 'pbeOID'
        //                         NULL                                 ==> no attributes here
        // ------------------------------------------------------------------------------------
        //             Sequence                                         ==> 'cipherInfo'
        //                 ObjectIdentifier(2.16.840.1.101.3.4.1.42)    ==> 'cipher
        //                 DER Octet String[16]                         ==> 'cipherIV'
        //                     cebdb51e05bbf8aecb47b3f5335d3bbe
        //     DER Octet String[1232]                                  ==> 'encryptedPrivateKey'
        //         6557ddc888

        try {
            final ASN1Sequence root;
            try (ASN1InputStream stream = new ASN1InputStream(blob)) {
                root = ASN1Sequence.getInstance(stream.readObject());
            }

            if (config.getLogger().isEnabled(Logger.DEBUG)) {
                config.getLogger().log(Logger.DEBUG, () -> "~~~ DecryptPKCS8#decrypt ~~~\n" +
                        ASN1Dump.dumpAsString(root, true));
            }

            // Object 0 in root: the parameters as a Sequence
            final ASN1Sequence algorithmHeaderSeq = ASN1Sequence.getInstance(root.getObjectAt(0));

            // Object 1 in root: the (encrypted) PrivateKey blob
            final byte[] encryptedPrivateKey = ASN1OctetString.getInstance(
                    root.getObjectAt(1)).getOctets();

            //        ObjectIdentifier with the privateKeyAlgorithm
            final ASN1ObjectIdentifier prvKeyAlgOID = ASN1ObjectIdentifier
                    .getInstance(algorithmHeaderSeq.getObjectAt(0));
            //        Sequence
            final ASN1Sequence attributeHeaderSeq = ASN1Sequence.getInstance(
                    algorithmHeaderSeq.getObjectAt(1));

            if (PKCSObjectIdentifiers.id_PBES2.equals(prvKeyAlgOID)) {

                final ASN1Sequence paramHeaderSeq = ASN1Sequence.getInstance(
                        attributeHeaderSeq.getObjectAt(0));
                final ASN1ObjectIdentifier paramOID = ASN1ObjectIdentifier
                        .getInstance(paramHeaderSeq.getObjectAt(0));
                final ASN1Sequence parameters = ASN1Sequence.getInstance(
                        paramHeaderSeq.getObjectAt(1));

                //        Sequence
                final ASN1Sequence cipherInfo = ASN1Sequence.getInstance(
                        attributeHeaderSeq.getObjectAt(1));
                //            ObjectIdentifier: the encryption algorithm
                final SshCipher cipher = getCipher(ASN1ObjectIdentifier.getInstance(
                        cipherInfo.getObjectAt(0)));
                //            DER Octet String[16]: the encryption IV
                final byte[] cipherIV = ASN1OctetString.getInstance(cipherInfo.getObjectAt(1))
                                                       .getOctets();

                if (cipherIV == null) {
                    // should never happen unless cipherInfo.getObjectAt(1) was somehow corrupted
                    throw new KeyException("Cipher/iv not set");
                }

                if (PKCSObjectIdentifiers.id_PBKDF2.equals(paramOID)) {
                    return decryptPBKDF2(encryptedPrivateKey, passphrase, parameters,
                                         cipher, cipherIV);
                } else if (MiscObjectIdentifiers.id_scrypt.equals(paramOID)) {
                    return decryptSCrypt(encryptedPrivateKey, passphrase, parameters,
                                         cipher, cipherIV);
                } else {
                    throw new KeyException("Unsupported parameter OID: " + paramOID);
                }
            } else {
                throw new KeyException("Unsupported algorithm: " + prvKeyAlgOID);
            }

        } finally {
            Arrays.fill(passphrase, (byte) 0);
        }
    }

    private byte[] decryptSCrypt(@NonNull final byte[] encryptedPrivateKey,
                                 @NonNull final byte[] passphrase,
                                 @NonNull final ASN1Encodable paramSequence,
                                 @NonNull final SshCipher cipher,
                                 @NonNull final byte[] cipherIV)
            throws GeneralSecurityException {
        //   scrypt-params ::= SEQUENCE {
        //       salt OCTET STRING,
        //       costParameter INTEGER (1..MAX),
        //       blockSize INTEGER (1..MAX),
        //       parallelizationParameter INTEGER (1..MAX),
        //       keyLength INTEGER (1..MAX) OPTIONAL
        //   }

        final ASN1Sequence attributes = ASN1Sequence.getInstance(paramSequence);
        final byte[] salt = ASN1OctetString.getInstance(attributes.getObjectAt(0))
                                           .getOctets();
        final int cost = ASN1Integer.getInstance(attributes.getObjectAt(1))
                                    .intValueExact();
        final int blockSize = ASN1Integer.getInstance(attributes.getObjectAt(2))
                                         .intValueExact();
        final int parallel = ASN1Integer.getInstance(attributes.getObjectAt(3))
                                        .intValueExact();
        if (attributes.size() > 4) {
            final int keyLength = ASN1Integer.getInstance(attributes.getObjectAt(4))
                                             .intValueExact();
        }

        byte[] pbeKey = null;
        final byte[] plainKey = new byte[encryptedPrivateKey.length];
        try {
            pbeKey = new PBKDFSCrypt()
                    .init(salt, cost, blockSize, parallel)
                    .generateSecretKey(passphrase, cipher.getKeySize());

            cipher.init(Cipher.DECRYPT_MODE, pbeKey, cipherIV);
            cipher.doFinal(encryptedPrivateKey, 0, encryptedPrivateKey.length, plainKey, 0);

        } finally {
            if (pbeKey != null) {
                Arrays.fill(pbeKey, (byte) 0);
            }
        }
        return plainKey;
    }

    // PKCS5 Params
    @NonNull
    private byte[] decryptPBKDF2(@NonNull final byte[] encryptedPrivateKey,
                                 @NonNull final byte[] passphrase,
                                 @NonNull final ASN1Encodable paramSequence,
                                 @NonNull final SshCipher cipher,
                                 @NonNull final byte[] cipherIV)
            throws GeneralSecurityException {
        //                 ObjectIdentifier(1.2.840.113549.1.5.12)      ==> 'paramOID'
        //                 Sequence                                     ==> 'parameters'
        //                     DER Octet String[8]                      ==> 'salt'
        //                         29a1b47e62a1997c
        //                     Integer(2048)                            ==> 'iterations'
        //                     Sequence                                 ==> 'yaSeq'
        //                         ObjectIdentifier(1.2.840.113549.2.9) ==> 'pbeOID'
        //                         NULL                                 ==> no attributes here


        //             Sequence
        final ASN1Sequence parameters = ASN1Sequence.getInstance(paramSequence);
        //                DER Octet String[8]
        final byte[] salt = ASN1OctetString.getInstance(parameters.getObjectAt(0))
                                           .getOctets();
        //                Integer(2048)
        final int iterations = ASN1Integer.getInstance(parameters.getObjectAt(1))
                                          .intValueExact();
        //                Sequence
        final ASN1Sequence yaSeq = ASN1Sequence.getInstance(parameters.getObjectAt(2));
        //                    ObjectIdentifier
        final ASN1ObjectIdentifier pbeOID =
                ASN1ObjectIdentifier.getInstance(yaSeq.getObjectAt(0));
        //                    NULL: no attributes

        byte[] pbeKey = null;
        final byte[] plainKey = new byte[encryptedPrivateKey.length];
        try {
            pbeKey = new PBKDFJCE()
                    .init(getPBEAlgorithm(pbeOID), salt, iterations)
                    .generateSecretKey(passphrase, cipher.getKeySize());

            cipher.init(Cipher.DECRYPT_MODE, pbeKey, cipherIV);
            cipher.doFinal(encryptedPrivateKey, 0, encryptedPrivateKey.length, plainKey, 0);

        } finally {
            if (pbeKey != null) {
                Arrays.fill(pbeKey, (byte) 0);
            }
        }
        return plainKey;

    }

    @NonNull
    private SshCipher getCipher(@NonNull final ASN1ObjectIdentifier id)
            throws NoSuchAlgorithmException {
        final String sshName;
        if (NISTObjectIdentifiers.id_aes128_CBC.equals(id)) {
            sshName = "aes128-cbc";
        } else if (NISTObjectIdentifiers.id_aes192_CBC.equals(id)) {
            sshName = "aes192-cbc";
        } else if (NISTObjectIdentifiers.id_aes256_CBC.equals(id)) {
            sshName = "aes256-cbc";
        } else {
            throw new NoSuchAlgorithmException("Not supported: " + id);
        }
        return ImplementationFactory.getCipher(config, sshName);
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
}
