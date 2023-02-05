package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.keypair.decryptors.DecryptPKCS8;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import java.security.GeneralSecurityException;

/**
 * A PKCS#8 KeyPair is a wrapper containing the actual KeyPair as {@link #delegate}.
 * <p>
 * The type / {@link #delegate} is available after a {@link #parsePrivateKey} when constructing.
 * Decrypting passphrase protected keys is as normal with {@link #decryptPrivateKey(byte[])}.
 * <p>
 * Keys are usually created with:
 * <pre>
 *      1. Create key pair
 *          openssl genrsa -out keypair.pem 2048
 *
 *      2. Extract public part
 *          openssl rsa -in keypair.pem -pubout -out publickey.crt
 *
 *      3. Extract private part (unencrypted)
 *          openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in keypair.pem -out pkcs8.key
 * </pre>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2898#section-6.2>
 * RFC 2898 PKCS#5 Password-Based Cryptography Specification, section 6.2. PBES2</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc5958">
 * RFC 5958 Asymmetric Key Packages</a> obsoletes 5208
 */
public final class KeyPairPKCS8
        extends DelegatingKeyPair {

    /**
     * Constructor.
     */
    private KeyPairPKCS8(@NonNull final SshClientConfig config,
                         @NonNull final Builder builder)
            throws GeneralSecurityException {
        super(config, builder.privateKeyBlob, PrivateKeyEncoding.PKCS8,
              builder.encrypted, new DecryptPKCS8(config));

        parse();
    }

    @Override
    void parsePrivateKey(@NonNull final byte[] encodedKey,
                         @NonNull final PrivateKeyEncoding encoding)
            throws GeneralSecurityException {

        if (delegate != null) {
            delegate.parsePrivateKey(encodedKey, encoding);
            return;
        }

        // Copy BEFORE we create the delegate
        final boolean privateKeyEncrypted = isPrivateKeyEncrypted();

        // parse the wrapper, and create the delegate
        try {
            final ASN1Sequence root;
            try (ASN1InputStream stream = new ASN1InputStream(encodedKey)) {
                root = ASN1Sequence.getInstance(stream.readObject());
            }
            if (config.getLogger().isEnabled(Logger.DEBUG)) {
                config.getLogger()
                      .log(Logger.DEBUG, () -> "~~~ KeyPairPKCS8#parsePrivateKey ~~~\n" +
                              ASN1Dump.dumpAsString(root, true));
            }

            final ASN1Sequence subSeq = ASN1Sequence.getInstance(root.getObjectAt(1));
            final ASN1ObjectIdentifier prvKeyAlgOID = ASN1ObjectIdentifier
                    .getInstance(subSeq.getObjectAt(0));

            if (PKCSObjectIdentifiers.rsaEncryption.equals(prvKeyAlgOID)) {
                delegate = (KeyPairBase) new KeyPairRSA.Builder(config)
                        .setPrivateKey(encodedKey)
                        .setFormat(PrivateKeyEncoding.PKCS8)
                        .setDecryptor(decryptor)
                        .build();

            } else if (X9ObjectIdentifiers.id_dsa.equals(prvKeyAlgOID)) {
                delegate = (KeyPairBase) new KeyPairDSA.Builder(config)
                        .setPrivateKey(encodedKey)
                        .setFormat(PrivateKeyEncoding.PKCS8)
                        .setDecryptor(decryptor)
                        .build();

            } else if (X9ObjectIdentifiers.id_ecPublicKey.equals(prvKeyAlgOID)) {
                delegate = (KeyPairBase) new KeyPairECDSA.Builder(config)
                        .setPrivateKey(encodedKey)
                        .setFormat(PrivateKeyEncoding.PKCS8)
                        .setDecryptor(decryptor)
                        .build();

            } else if (EdECObjectIdentifiers.id_Ed25519.equals(prvKeyAlgOID)
                    || EdECObjectIdentifiers.id_Ed448.equals(prvKeyAlgOID)) {
                delegate = (KeyPairBase) new KeyPairEdDSA.Builder(config)
                        .setPrivateKey(encodedKey)
                        .setFormat(PrivateKeyEncoding.PKCS8)
                        .setDecryptor(decryptor)
                        .build();

            } else {
                throw new UnsupportedAlgorithmException(String.valueOf(prvKeyAlgOID));
            }

            // now set the previously stored key/comment
            delegate.setEncodedPublicKey(publicKeyBlob, publicKeyBlobFormat);
            delegate.setPublicKeyComment(publicKeyComment);
            delegate.setPrivateKeyEncrypted(privateKeyEncrypted);

        } catch (@NonNull final GeneralSecurityException e) {
            // We have an actual error
            throw e;

        } catch (@NonNull final Exception ignore) {
            if (config.getLogger().isEnabled(Logger.DEBUG)) {
                config.getLogger().log(Logger.DEBUG, () -> DEBUG_KEY_PARSING_FAILED);
            }
        }
    }

    public static class Builder {

        @NonNull
        final SshClientConfig config;
        private byte[] privateKeyBlob;
        private boolean encrypted;

        public Builder(@NonNull final SshClientConfig config) {
            this.config = config;
        }

        /**
         * Set the private key blob.
         *
         * @param privateKeyBlob The encoded private key
         * @param encrypted      flag
         */
        @NonNull
        public Builder setPrivateKey(@NonNull final byte[] privateKeyBlob,
                                     final boolean encrypted) {
            this.privateKeyBlob = privateKeyBlob;
            this.encrypted = encrypted;
            return this;
        }

        @NonNull
        public SshKeyPair build()
                throws GeneralSecurityException {
            return new KeyPairPKCS8(config, this);
        }
    }
}
