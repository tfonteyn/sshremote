package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.ciphers.SshCipher;
import com.hardbacknutter.sshclient.keypair.util.Vendor;
import com.hardbacknutter.sshclient.pbkdf.PBKDF;
import com.hardbacknutter.sshclient.pbkdf.PBKDFJCE;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;

@SuppressWarnings("FieldNotUsedInToString")
class PrivateKeyBlob {

    @NonNull
    private final SshClientConfig config;
    @Nullable
    private byte[] blob;
    /** The format of the key blob */
    @Nullable
    private Vendor format;

    /** Whether the key is encrypted with a passphrase or not. */
    private boolean encrypted;
    /** key is encrypted - the cipher. */
    @Nullable
    private SshCipher cipher;
    /** key is encrypted - the IV for the cipher. */
    @Nullable
    protected byte[] cipherIV;
    @Nullable
    protected PBKDF pbkdf;

    /**
     * Constructor.
     */
    PrivateKeyBlob(@NonNull final SshClientConfig config) {
        this.config = config;
    }

    /**
     * Get the key blob in the current format (encrypted or not)
     *
     * @return key blob
     */
    @Nullable
    public byte[] getBlob() {
        return blob;
    }

    public void setBlob(@Nullable final byte[] blob) {
        this.blob = blob;
    }

    @Nullable
    public Vendor getFormat() {
        return format;
    }

    public void setFormat(@Nullable final Vendor format) {
        this.format = format;
    }

    public void setPBKDF(@Nullable final PBKDF pbkdf) {
        this.pbkdf = pbkdf;
    }

    public boolean isEncrypted() {
        return encrypted;
    }

    public void setEncrypted(final boolean encrypted) {
        this.encrypted = encrypted;
    }

    @Nullable
    public SshCipher getCipher() {
        return cipher;
    }

    public void setCipher(@NonNull final SshCipher cipher) {
        this.cipher = cipher;
    }

    @Nullable
    byte[] getCipherIV() {
        return cipherIV;
    }

    void setCipherIV(@Nullable final byte[] cipherIV) {
        this.cipherIV = cipherIV;
    }

    /**
     * If the blob was not encrypted, we return the blob directly.
     * <p>
     * If it was encrypted, we return the decrypted blob.
     * IMPORTANT: the returned byte[] CAN BE GARBAGE if the data/parameters were incorrect.
     * <p>
     * The returned value MUST be parsed for validity.
     */
    @NonNull
    public byte[] decrypt(@Nullable final byte[] passphrase)
            throws GeneralSecurityException, IOException {
        if (blob == null) {
            throw new InvalidKeyException("No key data");
        }

        if (!encrypted) {
            return blob;
        }

        if (passphrase == null) {
            throw new KeyException("Key is encrypted and no passphrase available");
        }

        if (format == null) {
            throw new KeyException("Key format not set");
        }

        byte[] pbeKey = null;
        try {
            if (format == Vendor.PKCS8) {
                // The Cipher/iv and PBKDF parameters are all embedded inside the blob
                return decryptPKCS8(passphrase);

            } else {
                if (cipher == null || cipherIV == null) {
                    throw new KeyException("Cipher/iv not set");
                }

                switch (format) {
                    case PKCS5: {
                        /*
                         * https://datatracker.ietf.org/doc/html/rfc8018#section-5.1
                         * PBKDF1
                         * hash is MD5
                         * h(0) <- hash(passphrase, iv);
                         * h(n) <- hash(h(n-1), passphrase, iv);
                         * key <- (h(0),...,h(n))[0,..,key.length];
                         */
                        final MessageDigest md5 = MessageDigest.getInstance("MD5");
                        final int hashSize = md5.getDigestLength();
                        final byte[] hn = new byte[cipher.getKeySize() / hashSize * hashSize +
                                (cipher.getKeySize() % hashSize
                                        == 0 ? 0 : hashSize)];
                        byte[] tmp = null;
                        for (int index = 0; index + hashSize <= hn.length; ) {
                            if (tmp != null) {
                                md5.update(tmp, 0, tmp.length);
                            }
                            md5.update(passphrase, 0, passphrase.length);
                            md5.update(cipherIV, 0, Math.min(cipherIV.length, 8));

                            tmp = md5.digest();
                            System.arraycopy(tmp, 0, hn, index, tmp.length);
                            index += tmp.length;
                        }
                        pbeKey = new byte[cipher.getKeySize()];
                        System.arraycopy(hn, 0, pbeKey, 0, pbeKey.length);
                        break;
                    }
                    case PUTTY3: {
                        //TODO: is this length correct?
                        byte[] tmp = new byte[cipher.getBlockSize() + cipher.getIVSize() + 32];
                        Objects.requireNonNull(pbkdf, "PUTTY3 encrypted but no pbkdf?");
                        tmp = pbkdf.generateSecretKey(passphrase, tmp.length);

                        pbeKey = new byte[cipher.getKeySize()];
                        System.arraycopy(tmp, 0, pbeKey, 0, pbeKey.length);
                        System.arraycopy(tmp, pbeKey.length, cipherIV, 0, cipherIV.length);
                        break;
                    }
                    case PUTTY2: {
                        // PuTTY PPK-2 files uses a hardcoded MessageDigest
                        Objects.requireNonNull(pbkdf, "PUTTY2 encrypted but no pbkdf?");
                        pbeKey = pbkdf.generateSecretKey(passphrase, 32);
                        break;
                    }

                    case OPENSSH_V1:
                        // handled inside the KeyPairOpenSSHv1 class
                    default:
                        throw new InvalidKeyException("Unexpected value: " + format);
                }

                final byte[] plainKey = new byte[blob.length];

                cipher.init(Cipher.DECRYPT_MODE, pbeKey, cipherIV);
                cipher.doFinal(blob, 0, blob.length, plainKey, 0);
                return plainKey;

            }
        } finally {
            if (pbeKey != null) {
                Arrays.fill(pbeKey, (byte) 0);
            }
            Arrays.fill(passphrase, (byte) 0);
        }
    }

    @NonNull
    private byte[] decryptPKCS8(@NonNull final byte[] passphrase)
            throws GeneralSecurityException, IOException {

        // RSA encrypted with prvKeyAlgOID == id_PBES2
        // Sequence                                                     ==> 'root'
        //     Sequence                                                 ==> 'subSeq'
        //         ObjectIdentifier(1.2.840.113549.1.5.13)              ==> 'prvKeyAlgOID'
        //         Sequence                                             ==> 'attributes'
        //             Sequence                                         ==> 'encAttrs'
        //                 ObjectIdentifier(1.2.840.113549.1.5.12)
        //                 Sequence                                     ==> 'pkcs5Params'
        //                     DER Octet String[8]                      ==> 'salt'
        //                         29a1b47e62a1997c
        //                     Integer(2048)                            ==> 'iterations'
        //                     Sequence                                 ==> 'yaSeq'
        //                         ObjectIdentifier(1.2.840.113549.2.9) ==> 'pbeOID'
        //                         NULL                                 ==> no attributes here
        //             Sequence                                         ==> 'cipherInfo'
        //                 ObjectIdentifier(2.16.840.1.101.3.4.1.42)    ==> 'encOID' ==> 'cipher
        //                 DER Octet String[16]                         ==> 'cipherIV'
        //                     cebdb51e05bbf8aecb47b3f5335d3bbe
        //     DER Octet String[1232]                                   ==> 'encryptedPrivateKey'
        //         6557ddc888


        //noinspection ConstantConditions
        final ASN1InputStream stream = new ASN1InputStream(blob);
        final ASN1Sequence root = ASN1Sequence.getInstance(stream.readObject());

        if (config.getLogger().isEnabled(Logger.DEBUG)) {
            config.getLogger().log(Logger.DEBUG, () -> "~~~ PrivateKeyBlob#decryptPKCS8 ~~~\n" +
                    ASN1Dump.dumpAsString(root, true));
        }

        //    Sequence
        final ASN1Sequence subSeq = ASN1Sequence.getInstance(root.getObjectAt(0));
        //        ObjectIdentifier privateKeyAlgorithm
        final ASN1ObjectIdentifier prvKeyAlgOID = ASN1ObjectIdentifier
                .getInstance(subSeq.getObjectAt(0));
        //        attributes: see below depending on algorithm

        // we now have access to the 'real' PrivateKey blob which is encrypted
        final byte[] encryptedPrivateKey = ASN1OctetString
                .getInstance(root.getObjectAt(1)).getOctets();

        if (PKCSObjectIdentifiers.id_PBES2.equals(prvKeyAlgOID)) {
            // 2nd step, actual decryption

            final ASN1Sequence attributes = ASN1Sequence.getInstance(subSeq.getObjectAt(1));
            final ASN1Sequence encAttrs = ASN1Sequence.getInstance(attributes.getObjectAt(0));

            final ASN1Sequence pkcs5Params = ASN1Sequence.getInstance(encAttrs.getObjectAt(1));
            //                DER Octet String[8]
            final byte[] salt = ASN1OctetString.getInstance(pkcs5Params.getObjectAt(0)).getOctets();
            //                Integer(2048)
            final int iterations = ASN1Integer.getInstance(pkcs5Params.getObjectAt(1))
                                              .intValueExact();
            //                Sequence
            final ASN1Sequence yaSeq = ASN1Sequence.getInstance(pkcs5Params.getObjectAt(2));
            //                    ObjectIdentifier
            final ASN1ObjectIdentifier pbeOID =
                    ASN1ObjectIdentifier.getInstance(yaSeq.getObjectAt(0));
            //                    NULL: no attributes

            //        Sequence
            final ASN1Sequence cipherInfo = ASN1Sequence.getInstance(attributes.getObjectAt(1));
            //            ObjectIdentifier: the encryption algorithm
            cipher = getCipher(ASN1ObjectIdentifier.getInstance(cipherInfo.getObjectAt(0)));
            //            DER Octet String[16]: the encryption IV
            cipherIV = ASN1OctetString.getInstance(cipherInfo.getObjectAt(1)).getOctets();

            if (cipherIV == null) {
                // should never happen unless cipherInfo.getObjectAt(1) was somehow corrupted
                throw new KeyException("Cipher/iv not set");
            }

            final byte[] plainKey = new byte[encryptedPrivateKey.length];
            byte[] pbeKey = null;
            try {
                pbeKey = new PBKDFJCE(pbeOID, salt, iterations)
                        .generateSecretKey(passphrase, cipher.getKeySize());

                cipher.init(Cipher.DECRYPT_MODE, pbeKey, cipherIV);
                cipher.doFinal(encryptedPrivateKey, 0, encryptedPrivateKey.length, plainKey, 0);

            } finally {
                if (pbeKey != null) {
                    Arrays.fill(pbeKey, (byte) 0);
                }
            }
            return plainKey;

        } else {
            throw new KeyException("Unsupported algorithm: " + prvKeyAlgOID);
        }
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

    public void dispose() {
        if (blob != null) {
            Arrays.fill(blob, (byte) 0);
        }
    }

    @Override
    @NonNull
    public String toString() {
        return "PrivateKeyBlob{" +
                "format=" + format +
                ", encrypted=" + encrypted +
                ", cipher=" + cipher +
                '}';
    }
}
