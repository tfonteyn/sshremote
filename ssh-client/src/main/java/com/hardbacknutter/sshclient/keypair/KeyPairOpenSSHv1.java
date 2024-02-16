package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.util.Objects;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.ciphers.SshCipherConstants;
import com.hardbacknutter.sshclient.hostkey.HostKeyAlgorithm;
import com.hardbacknutter.sshclient.keypair.pbkdf.DelegatingPBKDF;
import com.hardbacknutter.sshclient.keypair.pbkdf.PBKDFBCrypt;
import com.hardbacknutter.sshclient.utils.Buffer;
import com.hardbacknutter.sshclient.utils.ImplementationFactory;

/**
 * An OpenSSHv1 KeyPair is a wrapper containing an encrypted KeyPair.
 *
 * @see <a href="https://coolaj86.com/articles/the-openssh-private-key-format/">
 *         the-openssh-private-key-format</a>
 * @see <a href="http://dnaeon.github.io/openssh-private-key-binary-format/">
 *         openssh-private-key-binary-format</a>
 * @see <a href="http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.key?rev=HEAD">
 *         openbsd PROTOCOL</a>
 */
public final class KeyPairOpenSSHv1
        extends DelegatingKeyPair {
    private static final String KDFNAME_NONE = "none";
    private static final String KDFNAME_BCRYPT = "bcrypt";
    private static final byte[] AUTH_MAGIC = "openssh-key-v1\0".getBytes(StandardCharsets.UTF_8);
    /** key derivation function. */
    @Nullable
    private String kdfName;
    @Nullable
    private byte[] kdfOptions;

    /**
     * Constructor.
     */
    private KeyPairOpenSSHv1(@NonNull final SshClientConfig config,
                             @NonNull final Builder builder)
            throws GeneralSecurityException {
        super(config,
              Objects.requireNonNull(builder.privateKeyBlob),
              PrivateKeyEncoding.OPENSSH_V1,
              false,
              null);

        // public key blob is embedded in the private blob
        parsePrivateKey();
    }

    /**
     * reads openssh key v1 format and returns key type.
     */
    @NonNull
    public static String getHostKeyAlgorithm(@NonNull final byte[] blob)
            throws IOException, InvalidKeyException {

        final Buffer buffer = new Buffer(blob);
        // 64-bit dummy checksum  # a random 32-bit int, repeated
        final int checkInt1 = buffer.getInt();
        final int checkInt2 = buffer.getInt();
        if (checkInt1 != checkInt2) {
            throw new InvalidKeyException("checksum failed");
        }

        return HostKeyAlgorithm.parseType(buffer.getJString());
    }

    @Override
    void parsePrivateKey(@NonNull final byte[] encodedKey,
                         @NonNull final PrivateKeyEncoding encoding)
            throws GeneralSecurityException {
        if (getDelegate() != null) {
            getDelegate().parsePrivateKey(encodedKey, encoding);
            return;
        }

        try {
            final Buffer buffer = new Buffer(encodedKey);
            // "openssh-key-v1"0x00    # NULL-terminated "Auth Magic" string
            buffer.setReadOffSet(AUTH_MAGIC.length);
            // cipher
            final String cipherName = buffer.getJString();

            kdfName = buffer.getJString();
            kdfOptions = buffer.getString();

            // number of keys, for now always hard-coded to 1
            final int nrKeys = buffer.getInt();
            if (nrKeys != 1) {
                throw new UnsupportedKeyBlobEncodingException("Expected 1 key but found: "
                                                              + nrKeys);
            }
            // public key encoded in ssh format
            publicKeyEncodedBlob = buffer.getString();
            publicKeyBlobFormat = PublicKeyEncoding.OPENSSH_V1;

            // private key encoded in ssh format
            // REPLACE the blob. THE BUFFER IS NOW INVALID.
            privateKeyBlob = buffer.getString();

            if (!SshCipherConstants.NONE.equals(cipherName) && !KDFNAME_NONE.equals(kdfName)) {
                // The type can only be determined after decryption.
                // Set a deferred decryptor which acts a a placeholder for the cipher.
                decryptor = new DelegatingPBKDF();
                decryptor.setCipher(ImplementationFactory.getCipher(config, cipherName));
                setPrivateKeyEncrypted(true);
            } else {
                setPrivateKeyEncrypted(false);
                createDelegate(getHostKeyAlgorithm(privateKeyBlob), privateKeyBlob);
            }
        } catch (@NonNull final GeneralSecurityException e) {
            // We have an actual error
            throw e;

        } catch (@NonNull final Exception ignore) {
            config.getLogger().log(Logger.DEBUG, () -> DEBUG_KEY_PARSING_FAILED);
        }
    }

    @Override
    public boolean decrypt(@Nullable final byte[] passphrase)
            throws GeneralSecurityException, IOException {
        if (!isEncrypted()) {
            return true;
        }

        final byte[] plainKey;

        if (kdfName == null || KDFNAME_NONE.equals(kdfName)) {
            // sanity check, if we had an unencrypted key, then we would never get here
            // as the Builder would have created the KeyPair directly.
            throw new IllegalStateException("Unencrypted deferred KeyPair... that's a bug");

        } else if (KDFNAME_BCRYPT.equals(kdfName)) {
            Objects.requireNonNull(kdfOptions);
            // 2. KDF options for "bcrypt"
            //	string salt
            //	uint32 rounds
            final Buffer opts = new Buffer(kdfOptions);
            final byte[] salt = opts.getString();
            final int rounds = opts.getInt();

            //noinspection DataFlowIssue
            ((DelegatingPBKDF) decryptor)
                    .setDelegate(new PBKDFBCrypt().init(salt, rounds));

            plainKey = internalDecrypt(passphrase);
            // We MUST try parsing first to determine if it decrypted ok, or not!
            parsePrivateKey(plainKey, PrivateKeyEncoding.OPENSSH_V1);

        } else {
            throw new UnsupportedAlgorithmException(kdfName);
        }

        createDelegate(getHostKeyAlgorithm(plainKey), plainKey);

        //noinspection DataFlowIssue
        return !getDelegate().isEncrypted();
    }

    public static class Builder {

        @NonNull
        final SshClientConfig config;

        @Nullable
        private byte[] privateKeyBlob;


        public Builder(@NonNull final SshClientConfig config) {
            this.config = config;
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

        @NonNull
        public SshKeyPair build()
                throws GeneralSecurityException, IOException {
            return new KeyPairOpenSSHv1(config, this);
        }
    }
}
