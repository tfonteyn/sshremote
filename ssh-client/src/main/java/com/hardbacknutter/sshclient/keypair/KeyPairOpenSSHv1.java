package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.keypair.decryptors.DecryptBCrypt;
import com.hardbacknutter.sshclient.keypair.decryptors.DecryptDeferred;
import com.hardbacknutter.sshclient.keypair.decryptors.PKDecryptor;
import com.hardbacknutter.sshclient.utils.Buffer;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Objects;

/**
 * An OpenSSHv1 KeyPair is a wrapper containing a generic encrypted KeyPair.
 * <p>
 * If the wrapped key is NOT encrypted, the {@link Builder}
 * will detect the actual type and create the actual KeyPair directly.
 * If it IS encrypted, this class behaves will use a delegate after decryption.
 */
public final class KeyPairOpenSSHv1
        extends DelegatingKeyPair {
    private static final String UNKNOWN_KEY_TYPE_VENDOR = "Unknown key type/vendor";
    @SuppressWarnings("WeakerAccess")
    public static final String KDFNAME_NONE = "none";
    @SuppressWarnings("WeakerAccess")
    public static final String KDFNAME_BCRYPT = "bcrypt";

    /** key derivation function. */
    @Nullable
    private final String kdfName;
    @Nullable
    private final byte[] kdfOptions;

    /**
     * Constructor.
     */
    private KeyPairOpenSSHv1(@NonNull final SshClientConfig config,
                             @NonNull final Builder builder)
            throws GeneralSecurityException {
        super(config, builder.privateKeyBlob, Vendor.OPENSSH_V1,
              builder.decryptor != null, builder.decryptor);

        this.kdfName = builder.kdfName;
        this.kdfOptions = builder.kdfOptions;

        parse();
    }

    /**
     * reads openssh key v1 format and returns key type.
     */
    @NonNull
    public static String getHostKeyAlgorithm(@NonNull final byte[] blob)
            throws IOException, InvalidKeyException {

        if (blob.length % 8 != 0) {
            throw new IOException("The private key must be a multiple of the block size (8)");
        }

        final Buffer buffer = new Buffer(blob);
        // 64-bit dummy checksum  # a random 32-bit int, repeated
        final int checkInt1 = buffer.getInt();
        final int checkInt2 = buffer.getInt();
        if (checkInt1 != checkInt2) {
            throw new InvalidKeyException("checksum failed");
        }

        final String sshName = buffer.getJString();
        // the rest of the buffer contains the actual key data - not needed here.

        return HostKeyAlgorithm.parseType(sshName);
    }

    @Override
    void parsePrivateKey(@NonNull final byte[] encodedKey,
                         @NonNull final Vendor keyFormat)
            throws GeneralSecurityException {
        if (delegate != null) {
            delegate.parsePrivateKey(encodedKey, keyFormat);
        }
        //nothing to parse until the key is decrypted.
    }

    @Override
    public boolean decryptPrivateKey(@Nullable final byte[] passphrase)
            throws GeneralSecurityException, IOException {
        if (!isPrivateKeyEncrypted()) {
            return true;
        }

        final byte[] plainKey;

        if (kdfName == null || KDFNAME_NONE.equals(kdfName)) {
            // sanity check, if we had an unencrypted key, then we would never get here
            // as the Builder would have created the KeyPair directly.
            throw new IllegalStateException("Unencrypted deferred KeyPair... that's a bug");

        } else if (KDFNAME_BCRYPT.equals(kdfName)) {
            Objects.requireNonNull(kdfOptions, "bcrypt kdfOptions are null");
            // 2. KDF options for "bcrypt"
            //	string salt
            //	uint32 rounds
            final Buffer opts = new Buffer(kdfOptions);
            final byte[] salt = opts.getString();
            final int rounds = opts.getInt();

            //noinspection ConstantConditions
            ((DecryptDeferred) decryptor)
                    .setDelegate(new DecryptBCrypt().init(salt, rounds));

            plainKey = decrypt(passphrase);
            // We MUST try parsing first to determine if it decrypted ok, or not!
            parsePrivateKey(plainKey, Vendor.OPENSSH_V1);

        } else {
            throw new IllegalStateException("No support for KDF '" + kdfName + "'.");
        }

        // Use the builder again, this time with an unencrypted key
        // and the HostKeyAlgorithm derived from that key
        delegate = (KeyPairBase) new Builder(config)
                .setHostKeyAlgorithm(getHostKeyAlgorithm(plainKey))
                .setPrivateKey(plainKey)
                .build();

        // now set the previously stored key/comment
        delegate.setEncodedPublicKey(publicKeyBlob, publicKeyBlobFormat);
        delegate.setPublicKeyComment(publicKeyComment);

        return !delegate.isPrivateKeyEncrypted();
    }

    public static class Builder {

        @NonNull
        final SshClientConfig config;
        @Nullable
        private String hostKeyAlgorithm;

        @Nullable
        private String kdfName;
        @Nullable
        private byte[] kdfOptions;

        private byte[] privateKeyBlob;
        @Nullable
        private PKDecryptor decryptor;

        public Builder(@NonNull final SshClientConfig config) {
            this.config = config;
        }

        @NonNull
        public Builder setHostKeyAlgorithm(@NonNull final String type)
                throws InvalidKeyException {
            this.hostKeyAlgorithm = HostKeyAlgorithm.parseType(type);
            return this;
        }

        @SuppressWarnings("UnusedReturnValue")
        @NonNull
        public Builder setKDF(@NonNull final String kdfName,
                              @NonNull final byte[] kdfOptions) {
            this.kdfName = kdfName;
            this.kdfOptions = kdfOptions;
            return this;
        }

        /**
         * Set the private key blob.
         *
         * @param privateKeyBlob The encoded private key
         */
        @NonNull
        public Builder setPrivateKey(@NonNull final byte[] privateKeyBlob) {
            this.privateKeyBlob = privateKeyBlob;
            return this;
        }

        /**
         * Set the optional decryptor to use if the key is encrypted.
         *
         * @param decryptor (optional) The vendor specific decryptor
         */
        @NonNull
        public Builder setDecryptor(@Nullable final PKDecryptor decryptor) {
            this.decryptor = decryptor;
            return this;
        }

        @NonNull
        public SshKeyPair build()
                throws GeneralSecurityException, IOException {

            if (hostKeyAlgorithm == null) {
                return new KeyPairOpenSSHv1(config, this);
            }

            switch (hostKeyAlgorithm) {
                case HostKeyAlgorithm.SSH_RSA:
                    return new KeyPairRSA.Builder(config)
                            .setPrivateKey(privateKeyBlob)
                            .setFormat(Vendor.OPENSSH_V1)
                            .setDecryptor(decryptor)
                            .build();

                case HostKeyAlgorithm.SSH_DSS:
                    return new KeyPairDSA.Builder(config)
                            .setPrivateKey(privateKeyBlob)
                            .setFormat(Vendor.OPENSSH_V1)
                            .setDecryptor(decryptor)
                            .build();

                case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256:
                case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384:
                case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521:
                    return new KeyPairECDSA.Builder(config)
                            .setHostKeyAlgorithm(hostKeyAlgorithm)
                            .setPrivateKey(privateKeyBlob)
                            .setFormat(Vendor.OPENSSH_V1)
                            .setDecryptor(decryptor)
                            .build();

                case HostKeyAlgorithm.SSH_ED25519:
                case HostKeyAlgorithm.SSH_ED448:
                    return new KeyPairEdDSA.Builder(config)
                            .setHostKeyAlgorithm(hostKeyAlgorithm)
                            .setPrivateKey(privateKeyBlob)
                            .setFormat(Vendor.OPENSSH_V1)
                            .setDecryptor(decryptor)
                            .build();

                default:
                    throw new InvalidKeyException(UNKNOWN_KEY_TYPE_VENDOR);
            }
        }
    }
}
