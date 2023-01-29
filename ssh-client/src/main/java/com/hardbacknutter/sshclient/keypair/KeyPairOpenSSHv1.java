package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.keypair.decryptors.DecryptBCrypt;
import com.hardbacknutter.sshclient.keypair.decryptors.DecryptDeferred;
import com.hardbacknutter.sshclient.keypair.decryptors.PKDecryptor;
import com.hardbacknutter.sshclient.keypair.util.OpenSSHv1Reader;
import com.hardbacknutter.sshclient.signature.SshSignature;
import com.hardbacknutter.sshclient.utils.Buffer;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Objects;

/**
 * An OpenSSHv1 KeyPair is a wrapper containing a generic encrypted KeyPair.
 * <p>
 * If the wrapped key is NOT encrypted, the {@link OpenSSHv1Reader} and {@link Builder}
 * will detect the actual type and create the actual KeyPair directly.
 * If it IS encrypted, this class behaves will use a delegate after decryption.
 */
@SuppressWarnings("ClassWithOnlyPrivateConstructors")
public
class KeyPairOpenSSHv1
        extends KeyPairBase {

    private static final String MUST_PARSE_FIRST = "Must call decrypt/parse first";
    private static final String UNKNOWN_KEY_TYPE_VENDOR = "Unknown key type/vendor";

    /** key derivation function. */
    @NonNull
    private final String kdfName;
    @NonNull
    private final byte[] kdfOptions;
    @Nullable
    private KeyPairBase delegate;

    /**
     * Constructor.
     */
    private KeyPairOpenSSHv1(@NonNull final SshClientConfig config,
                             @NonNull final Builder builder) {
        super(config, builder.privateKeyBlob);

        this.kdfName = Objects.requireNonNull(builder.kdfName, "kdfName is null");
        this.kdfOptions = Objects.requireNonNull(builder.kdfOptions, "kdfOptions is null");

        // delegate does not exist yet, this call would be a NOP.
        //parse();
    }

    @Override
    @NonNull
    public String getHostKeyAlgorithm()
            throws GeneralSecurityException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getHostKeyAlgorithm();
    }

    @Override
    public int getKeySize() {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getKeySize();
    }

    @Override
    @NonNull
    public byte[] getSignature(@NonNull final byte[] data,
                               @NonNull final String algorithm)
            throws GeneralSecurityException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getSignature(data, algorithm);
    }

    @Override
    @NonNull
    public SshSignature getVerifier(@NonNull final String algorithm)
            throws GeneralSecurityException, IOException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getVerifier(algorithm);
    }

    @Override
    @NonNull
    public byte[] forSSHAgent()
            throws GeneralSecurityException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).forSSHAgent();
    }

    @Override
    public boolean isPrivateKeyEncrypted() {
        return delegate == null || delegate.isPrivateKeyEncrypted();
    }

    @Override
    void parse(@NonNull final byte[] encodedKey,
               @NonNull final Vendor keyFormat)
            throws GeneralSecurityException {
        if (delegate != null) {
            delegate.parse(encodedKey, keyFormat);
        }
    }

    @Override
    public void dispose() {
        if (delegate != null) {
            delegate.dispose();
        }
        super.dispose();
    }

    @Override
    @Nullable
    public byte[] getSshPublicKeyBlob()
            throws GeneralSecurityException {
        return delegate != null ? delegate.getSshPublicKeyBlob() : publicKeyBlob;
    }

    @Override
    @NonNull
    public String getPublicKeyComment() {
        return delegate != null ? delegate.getPublicKeyComment() : publicKeyComment;
    }

    @Override
    @Nullable
    public String getFingerPrint()
            throws GeneralSecurityException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getFingerPrint();
    }

    @Override
    @Nullable
    public String getFingerPrint(@NonNull final String algorithm)
            throws GeneralSecurityException {
        return Objects.requireNonNull(delegate, MUST_PARSE_FIRST).getFingerPrint(algorithm);
    }

    @Override
    public boolean decryptPrivateKey(@Nullable final byte[] passphrase)
            throws GeneralSecurityException, IOException {
        if (!privateKeyBlob.isEncrypted()) {
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
            ((DecryptDeferred) privateKeyBlob.getDecryptor())
                    .setDelegate(new DecryptBCrypt().init(salt, rounds));

            plainKey = privateKeyBlob.decrypt(passphrase);
            // We MUST try parsing first to determine if it decrypted ok, or not!
            parse(plainKey, Vendor.OPENSSH_V1);

        } else {
            throw new IllegalStateException("No support for KDF '" + kdfName + "'.");
        }

        // now we have the decrypted key and can thus determine the real type
        final String hostKeyType = OpenSSHv1Reader.getHostKeyType(plainKey);

        // Use the builder again, this time with an unencrypted key.
        delegate = (KeyPairBase) new Builder(config)
                .setHostKeyType(hostKeyType)
                .setPrivateKeyBlob(plainKey, Vendor.OPENSSH_V1, null)
                .build();

        delegate.setSshPublicKeyBlob(publicKeyBlob);
        delegate.setPublicKeyComment(publicKeyComment);

        // mirror the setting for sanity
        privateKeyBlob.setEncrypted(delegate.isPrivateKeyEncrypted());

        return !delegate.isPrivateKeyEncrypted();
    }

    public static class Builder {

        @NonNull
        final SshClientConfig config;
        @NonNull
        private String hostKeyType = HostKeyAlgorithm.__DEFERRED__;

        @Nullable
        private String kdfName;
        @Nullable
        private byte[] kdfOptions;

        @Nullable
        private byte[] publicKeyBlob;
        private PrivateKeyBlob privateKeyBlob;

        public Builder(@NonNull final SshClientConfig config) {
            this.config = config;
        }

        @NonNull
        public Builder setHostKeyType(@NonNull final String type)
                throws InvalidKeyException {
            this.hostKeyType = HostKeyAlgorithm.parseType(type);
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
            if (HostKeyAlgorithm.__DEFERRED__.equals(hostKeyType) && publicKeyBlob != null) {
                final Buffer pb = new Buffer(publicKeyBlob);
                try {
                    hostKeyType = HostKeyAlgorithm.parseType(pb.getJString());
                } catch (final IOException | InvalidKeyException ignore) {

                }
            }
            return this;
        }

        /**
         * Set the private key blob and its format.
         *
         * @param blob      The byte[] with the private key
         * @param format    The vendor specific format of the private key
         *                  This is independent from the encryption state.
         * @param decryptor (optional) The vendor specific decryptor
         */
        @NonNull
        public Builder setPrivateKeyBlob(@NonNull final byte[] blob,
                                         @NonNull final Vendor format,
                                         @Nullable final PKDecryptor decryptor) {
            privateKeyBlob = new PrivateKeyBlob(blob, format, decryptor);
            return this;
        }

        @NonNull
        public SshKeyPair build()
                throws GeneralSecurityException {

            if (hostKeyType.isBlank()) {
                throw new InvalidKeyException(UNKNOWN_KEY_TYPE_VENDOR);
            }

            final SshKeyPair keyPair;
            switch (hostKeyType) {
                case HostKeyAlgorithm.__DEFERRED__:
                    // encrypted
                    keyPair = new KeyPairOpenSSHv1(config, this);
                    break;

                case HostKeyAlgorithm.__PKCS8__:
                    // Does this situation actually exists in the real world?
                    keyPair = new KeyPairPKCS8(config, privateKeyBlob);
                    break;

                case HostKeyAlgorithm.SSH_RSA:
                    keyPair = new KeyPairRSA(config, privateKeyBlob);
                    break;

                case HostKeyAlgorithm.SSH_DSS:
                    keyPair = new KeyPairDSA(config, privateKeyBlob);
                    break;

                case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP256:
                case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP384:
                case HostKeyAlgorithm.SSH_ECDSA_SHA2_NISTP521:
                    keyPair = new KeyPairECDSA(config, privateKeyBlob,
                                               ECKeyType.getByHostKeyAlgorithm(hostKeyType));
                    break;

                case HostKeyAlgorithm.SSH_ED25519:
                case HostKeyAlgorithm.SSH_ED448:
                    keyPair = new KeyPairEdDSA(config, privateKeyBlob,
                                               EdKeyType.getByHostKeyAlgorithm(hostKeyType));
                    break;

                default:
                    throw new InvalidKeyException(UNKNOWN_KEY_TYPE_VENDOR);
            }

            keyPair.setSshPublicKeyBlob(publicKeyBlob);
            return keyPair;
        }
    }
}
