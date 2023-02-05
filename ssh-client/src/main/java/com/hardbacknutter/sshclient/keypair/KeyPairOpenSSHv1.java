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

    /** Flag to indicate the HostKeyAlgorithm is not known yet. */
    public static final String __OPENSSH_V1__ = "__OPENSSH_V1__";
    private static final String UNKNOWN_KEY_TYPE_VENDOR = "Unknown key type/vendor";

    /** key derivation function. */
    @NonNull
    private final String kdfName;
    @NonNull
    private final byte[] kdfOptions;

    /**
     * Constructor.
     */
    private KeyPairOpenSSHv1(@NonNull final SshClientConfig config,
                             @NonNull final Builder builder)
            throws GeneralSecurityException {
        super(config, builder.privateKeyBlob, Vendor.OPENSSH_V1,
              builder.decryptor != null, builder.decryptor);

        this.kdfName = Objects.requireNonNull(builder.kdfName, "kdfName is null");
        this.kdfOptions = Objects.requireNonNull(builder.kdfOptions, "kdfOptions is null");

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

        if ("none".equals(kdfName)) {
            // sanity check, if we had an unencrypted key, then we would never get here
            // as the Builder would have created the KeyPair directly.
            throw new IllegalStateException("Unencrypted deferred KeyPair... that's a bug");

        } else if ("bcrypt".equals(kdfName)) {
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
        // and the type derived from that key
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
        @NonNull
        private String hostKeyAlgorithm = __OPENSSH_V1__;

        @Nullable
        private String kdfName;
        @Nullable
        private byte[] kdfOptions;

        @Nullable
        private byte[] publicKeyBlob;
        private byte[] privateKeyBlob;
        @Nullable
        private PKDecryptor decryptor;

        public Builder(@NonNull final SshClientConfig config) {
            this.config = config;
        }

        @NonNull
        public Builder setHostKeyAlgorithm(@NonNull final String type)
                throws InvalidKeyException {
            if (__OPENSSH_V1__.equals(type)) {
                this.hostKeyAlgorithm = __OPENSSH_V1__;
            } else {
                this.hostKeyAlgorithm = HostKeyAlgorithm.parseType(type);
            }
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

        @SuppressWarnings("UnusedReturnValue")
        @NonNull
        public Builder setPublicKeyBlob(@Nullable final byte[] publicKeyBlob) {
            this.publicKeyBlob = publicKeyBlob;

            // if possible, use the type derived from the public key
            if (__OPENSSH_V1__.equals(hostKeyAlgorithm) && publicKeyBlob != null) {
                final Buffer pb = new Buffer(publicKeyBlob);
                try {
                    hostKeyAlgorithm = HostKeyAlgorithm.parseType(pb.getJString());
                } catch (final IOException | InvalidKeyException ignore) {

                }
            }
            return this;
        }

        /**
         * Set the private key blob.
         *
         * @param privateKeyBlob The byte[] with the private key
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

            if (hostKeyAlgorithm.isBlank()) {
                throw new InvalidKeyException(UNKNOWN_KEY_TYPE_VENDOR);
            }

            final SshKeyPair keyPair;
            switch (hostKeyAlgorithm) {
                case __OPENSSH_V1__:
                    keyPair = new KeyPairOpenSSHv1(config, this);
                    break;

                case HostKeyAlgorithm.SSH_RSA:
                    keyPair = new KeyPairRSA.Builder(config)
                            .setPrivateKey(privateKeyBlob)
                            .setFormat(Vendor.OPENSSH_V1)
                            .setDecryptor(decryptor)
                            .build();
                    break;

                case HostKeyAlgorithm.SSH_DSS:
                    keyPair = new KeyPairDSA.Builder(config)
                            .setPrivateKey(privateKeyBlob)
                            .setFormat(Vendor.OPENSSH_V1)
                            .setDecryptor(decryptor)
                            .build();
                    break;

                case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256:
                case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384:
                case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521:
                    keyPair = new KeyPairECDSA.Builder(config)
                            .setPrivateKey(privateKeyBlob)
                            .setFormat(Vendor.OPENSSH_V1)
                            .setDecryptor(decryptor)
                            .setType(ECKeyType.getByHostKeyAlgorithm(hostKeyAlgorithm))
                            .build();
                    break;

                case HostKeyAlgorithm.SSH_ED25519:
                case HostKeyAlgorithm.SSH_ED448:
                    keyPair = new KeyPairEdDSA.Builder(config)
                            .setPrivateKey(privateKeyBlob)
                            .setFormat(Vendor.OPENSSH_V1)
                            .setDecryptor(decryptor)
                            .setType(hostKeyAlgorithm)
                            .build();
                    break;

                default:
                    throw new InvalidKeyException(UNKNOWN_KEY_TYPE_VENDOR);
            }

            keyPair.setEncodedPublicKey(publicKeyBlob, PublicKeyFormat.OPENSSH_V1);
            return keyPair;
        }
    }
}
