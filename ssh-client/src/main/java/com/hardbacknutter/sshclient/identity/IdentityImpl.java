package com.hardbacknutter.sshclient.identity;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.keypair.SshKeyPair;
import com.hardbacknutter.sshclient.keypair.util.KeyPairParser;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * The default (internal) Identity implementation.
 */
public final class IdentityImpl
        implements Identity {

    @SuppressWarnings({"FieldCanBeLocal", "unused", "FieldNotUsedInToString"})
    @NonNull
    private final SshClientConfig config;
    @NonNull
    private final String name;
    @NonNull
    private final SshKeyPair sshKeyPair;

    public IdentityImpl(@NonNull final SshClientConfig config,
                        @NonNull final String name,
                        @NonNull final SshKeyPair sshKeyPair) {
        this.config = config;
        this.name = name;
        this.sshKeyPair = sshKeyPair;
    }

    /**
     * Creates a new Identity from the public and private key file names.
     * <p>
     * If a file with the same name and suffix {@code .pub}.
     * exists, it will be parsed for the public key.
     *
     * @param privateKeyFilename the file name of the private key file.
     *                           This is also used as the identifying name of the key.
     */
    @NonNull
    public static Identity fromFiles(@NonNull final SshClientConfig config,
                                     @NonNull final String privateKeyFilename)
            throws IOException, GeneralSecurityException {

        final KeyPairParser keyPairParser = new KeyPairParser(config);
        final SshKeyPair keyPair = keyPairParser.parse(privateKeyFilename);
        return new IdentityImpl(config, privateKeyFilename, keyPair);
    }

    @NonNull
    public static Identity fromFiles(@NonNull final SshClientConfig config,
                                     @NonNull final String privateKeyFilename,
                                     @Nullable final String publicKeyFilename)
            throws IOException, GeneralSecurityException {

        final KeyPairParser keyPairParser = new KeyPairParser(config);
        final SshKeyPair keyPair = keyPairParser.parse(privateKeyFilename, publicKeyFilename);
        return new IdentityImpl(config, privateKeyFilename, keyPair);
    }

    /**
     * Creates a new Identity from the public and private key data.
     * The private key array will be zeroed out after reading.
     */
    @NonNull
    public static Identity fromKeyData(@NonNull final SshClientConfig config,
                                       @NonNull final String name,
                                       @NonNull final byte[] prvKey,
                                       @Nullable final byte[] pubKey)
            throws IOException, GeneralSecurityException {

        final KeyPairParser keyPairParser = new KeyPairParser(config);
        final SshKeyPair keyPair = keyPairParser.parse(prvKey, pubKey);
        return new IdentityImpl(config, name, keyPair);
    }

    /**
     * Decrypts this identity with the specified pass-phrase.
     *
     * @param passphrase the pass-phrase for this identity.
     *                   a {@code null} is valid input as the identity CAN be unencrypted
     *
     * @return {@code true} if the decryption has succeeded
     * or if this identity is not encrypted.
     */
    @Override
    public boolean decrypt(@Nullable final byte[] passphrase)
            throws GeneralSecurityException, IOException {
        return sshKeyPair.decrypt(passphrase);
    }

    /**
     * Returns the blob of the public key in the <strong>SSH wrapped encoding</strong>.
     * <p>
     * string    format identifier
     * byte[n]   key data
     *
     * @return blob of the public key
     */
    @Override
    @NonNull
    public byte[] getSshEncodedPublicKey() {
        return sshKeyPair.getSshEncodedPublicKey();
    }

    @Override
    @NonNull
    public byte[] getSignature(@NonNull final byte[] data,
                               @NonNull final String algorithm)
            throws GeneralSecurityException {
        return sshKeyPair.getSignature(data, algorithm);
    }

    /**
     * Returns the name of the key algorithm.
     *
     * @return "ssh-rsa", "ssh-dss", "ecdsa-sha2-*", "ssh-ed25519" etc...
     */
    @Override
    @NonNull
    public String getHostKeyAlgorithm()
            throws GeneralSecurityException {
        return sshKeyPair.getHostKeyAlgorithm();
    }

    /**
     * Returns the name of this identity.
     * It will be useful to identify this object in the {@link IdentityRepository}.
     */
    @Override
    @NonNull
    public String getName() {
        return name;
    }

    /**
     * Returns {@code true} if this identity is encrypted.
     *
     * @return {@code true} if this identity is encrypted.
     */
    @Override
    public boolean isEncrypted() {
        return sshKeyPair.isEncrypted();
    }

    /**
     * Disposes internally allocated data, like byte array for the private key.
     */
    @Override
    public void clear() {
        sshKeyPair.dispose();
    }

    @Override
    @NonNull
    public String toString() {
        return "IdentityFile{"
                + "identity='" + name + '\''
                + ", sshKeyPair=" + sshKeyPair
                + '}';
    }
}
