package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.keypair.pbkdf.PBKDFPKCS8;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.util.ASN1Dump;

import java.security.GeneralSecurityException;
import java.util.Objects;

/**
 * A PKCS#8 KeyPair is a wrapper containing the actual KeyPair.
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
        super(config,
              Objects.requireNonNull(builder.privateKeyBlob),
              PrivateKeyEncoding.PKCS8,
              builder.encrypted,
              new PBKDFPKCS8(config));

        // public key blob is embedded in the private blob
        parsePrivateKey();
    }


    @Override
    void parsePrivateKey(@NonNull final byte[] encodedKey,
                         @NonNull final PrivateKeyEncoding encoding)
            throws GeneralSecurityException {

        if (getDelegate() != null) {
            getDelegate().parsePrivateKey(encodedKey, encoding);
            return;
        }

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

            createDelegate(prvKeyAlgOID, encodedKey);


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
        @Nullable
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
