package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.hostkey.HostKey;
import com.hardbacknutter.sshclient.identity.Identity;
import com.hardbacknutter.sshclient.identity.IdentityImpl;
import com.hardbacknutter.sshclient.keypair.decryptors.PKDecryptor;
import com.hardbacknutter.sshclient.utils.Buffer;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.util.Arrays;

/**
 * Base class for a pair of public and private key.
 * <p>
 * Copied from <a href="https://bugs.java.com/bugdatabase/view_bug.do?bug_id=6263419">
 * java bug 6263419</a>
 * We agree with this assessment.
 * We DO clear arrays as an extra effort but make no effort otherwise.
 */
@SuppressWarnings("FieldNotUsedInToString")
public abstract class KeyPairBase
        implements SshKeyPair {

    // This is NOT an error; it will happen when the key is encrypted
    // and we try to parse it without decoding correctly
    static final String DEBUG_KEY_PARSING_FAILED = "Parsing failed, key is still encrypted";

    @NonNull
    final SshClientConfig config;
    @Nullable
    PKDecryptor decryptor;
    /**
     * The encoded public key; if we have it, we use it directly, otherwise it will be
     * build from the key components at first use.
     */
    @Nullable
    private byte[] publicKeyBlob;
    @NonNull
    private String publicKeyComment = "";
    /**
     * The private key as a byte[].
     * The binary format is {@link #privateKeyFormat}.
     * It may be {@link #privateKeyEncrypted} or not.
     * If it is, then {@link #decryptor} should be able to decrypt it.
     */
    @Nullable
    private byte[] privateKeyBlob;
    @Nullable
    private Vendor privateKeyFormat;
    private boolean privateKeyEncrypted;

    /**
     * Constructor.
     */
    KeyPairBase(@NonNull final SshClientConfig config) {
        this.config = config;
    }

    /**
     * Constructor.
     *
     * @param encrypted flag; if {@code true} then 'decryptor' MUST be set.
     *                  if {@code false} then 'decryptor' only needs setting
     *                  if it will act as a wrapper/delegate (e.g. PKCS8).
     * @param decryptor (optional) The vendor specific decryptor
     */
    KeyPairBase(@NonNull final SshClientConfig config,
                @NonNull final byte[] privateKeyBlob,
                @NonNull final Vendor format,
                final boolean encrypted,
                @Nullable final PKDecryptor decryptor) {
        this.config = config;
        this.privateKeyBlob = privateKeyBlob;
        this.privateKeyFormat = format;
        this.privateKeyEncrypted = encrypted;
        this.decryptor = decryptor;
    }

    /**
     * Create the publicKey blob using the key algorithm,
     * and the list of the type specific parameters.
     * <p>
     * string    certificate or public key format identifier
     * byte[n]   key/certificate data
     *
     * @param keyAlgorithm identifier
     * @param args         key/certificate data
     *
     * @return the blob
     */
    @NonNull
    static byte[] wrapPublicKey(@NonNull final String keyAlgorithm,
                                @NonNull final byte[]... args) {
        // use a fixed-size buffer
        // (+4: a uint32 to store the length of the argument string)
        int length = 4 + keyAlgorithm.length();
        for (final byte[] arg : args) {
            length += 4 + arg.length;
        }

        final Buffer buffer = new Buffer(length)
                .putString(keyAlgorithm);
        for (final byte[] arg : args) {
            buffer.putString(arg);
        }
        return buffer.data;
    }

    /**
     * The resulting signature is encoded as follows:
     * <p>
     * string    "signature_name"
     * string    signature_blob
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-6.6">
     * RFC 4253 SSH Transport Layer Protocol, section 6.6.</a>
     */
    @NonNull
    static byte[] wrapSignature(@NonNull final String signature_name,
                                @NonNull final byte[] signature_blob) {
        // use a fixed-size buffer
        // (+4: a uint32 to store the length of the argument string)
        final Buffer buffer = new Buffer(4 + signature_name.length()
                                                 + 4 + signature_blob.length)
                .putString(signature_name)
                .putString(signature_blob);

        return buffer.data;
    }

    @Override
    @Nullable
    public byte[] getSshPublicKeyBlob()
            throws GeneralSecurityException {
        return publicKeyBlob;
    }

    public void setSshPublicKeyBlob(@Nullable final byte[] publicKeyBlob) {
        this.publicKeyBlob = publicKeyBlob;
    }

    @Override
    @NonNull
    public String getPublicKeyComment() {
        return publicKeyComment;
    }

    public void setPublicKeyComment(@Nullable final String comment) {
        this.publicKeyComment = comment != null ? comment : "";
    }

    @Override
    @Nullable
    public String getFingerPrint()
            throws GeneralSecurityException {
        final byte[] keyBlob = getSshPublicKeyBlob();
        if (keyBlob == null) {
            return null;
        }
        return HostKey.getFingerPrint(config, keyBlob);
    }

    @Override
    @Nullable
    public String getFingerPrint(@NonNull final String algorithm)
            throws GeneralSecurityException {
        final byte[] keyBlob = getSshPublicKeyBlob();
        if (keyBlob == null) {
            return null;
        }
        return HostKey.getFingerPrint(algorithm, keyBlob);
    }

    @NonNull
    @Override
    public Identity toIdentity(@NonNull final String name) {
        return new IdentityImpl(config, name, this);
    }

    @Override
    public boolean isPrivateKeyEncrypted() {
        return privateKeyEncrypted;
    }

    public void setPrivateKeyEncrypted(final boolean encrypted) {
        this.privateKeyEncrypted = encrypted;
    }

    /**
     * TRY to parse the <strong>unencrypted</strong> but encoded key blob.
     * <p>
     * This is a NOP if either the key blob or the format was {@code null}.
     *
     * @throws GeneralSecurityException if the key <strong>could</strong> be parsed but was invalid.
     */
    final void parse()
            throws GeneralSecurityException {
        if (privateKeyBlob != null && privateKeyFormat != null) {
            parse(privateKeyBlob, privateKeyFormat);
        }
    }

    /**
     * TRY to parse the <strong>unencrypted</strong> but encoded key blob.
     * This blob will normally always have the private key information,
     * and for some formats also the public key data.
     * <p>
     * The data must be in some format that the implementation can parse.
     * <p>
     * <strong>IMPORTANT: implementations MUST NOT assume that the 'encodedKey' and 'keyFormat'
     * are from the internal privateKeyBlob.
     * They MUST ONLY call {@code privateKeyBlob.setEncrypted(success)} with the outcome
     * </strong>
     *
     * @param encodedKey the unencrypted (plain) key data.
     * @param keyFormat  the encoding format
     *
     * @throws GeneralSecurityException if the key <strong>could</strong> be parsed but was invalid.
     */
    abstract void parse(@NonNull byte[] encodedKey,
                        @NonNull final Vendor keyFormat)
            throws GeneralSecurityException;

    /**
     * Decrypts the private key, using a passphrase.
     * <p>
     * This call is safe to call even if the key is not encrypted.
     * Hence passing in a {@code null} passphrase is valid.
     *
     * @return {@code true} if the private key was successfully
     * decrypted, i.e. is now usable, else {@code false}.
     */
    @Override
    public boolean decryptPrivateKey(@Nullable final byte[] passphrase)
            throws GeneralSecurityException, IOException {

        if (!privateKeyEncrypted) {
            return true;
        }

        // sanity check
        if (privateKeyFormat == null) {
            return false;
        }

        final byte[] plainKey;
        try {
            plainKey = decrypt(passphrase);
            // be optimistic, assume all went well
            privateKeyEncrypted = false;
        } catch (final GeneralSecurityException e) {
            // We have an actual error
            throw e;
        } catch (@NonNull final Exception e) {
            if (config.getLogger().isEnabled(Logger.DEBUG)) {
                config.getLogger().log(Logger.DEBUG, e, () -> "decrypt");
            }

            // failed due to a key format decoding problem
            privateKeyEncrypted = true;
            return false;
        }

        // Decrypt went fine, but if for example the passphrase was incorrect,
        // then the plain key would be garbage hence the next step is to parse it.
        parse(plainKey, privateKeyFormat);

        if (privateKeyEncrypted) {
            return false;
        }

        // Success! Replace the encrypted key with the now plain key
        privateKeyBlob = plainKey;
        return true;
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
        if (privateKeyBlob == null) {
            throw new InvalidKeyException("No key data");
        }

        if (!privateKeyEncrypted) {
            return privateKeyBlob;
        }

        if (passphrase == null) {
            throw new KeyException("Passphrase not set");
        }

        if (decryptor == null) {
            throw new KeyException("PKDecryptor not set");
        }

        return decryptor.decrypt(passphrase, privateKeyBlob);
    }

    @Override
    public void dispose() {
        if (privateKeyBlob != null) {
            Arrays.fill(privateKeyBlob, (byte) 0);
        }
    }

    @Override
    @NonNull
    public String toString() {
        return "KeyPairBase{"
                + "privateKeyBlob=" + Arrays.toString(privateKeyBlob)
                + ", publicKeyBlob=" + Arrays.toString(publicKeyBlob)
                + ", publicKeyComment='" + publicKeyComment + '\''
                + "}";
    }

    /**
     * Called by the garbage collector when the object is not reachable anymore.
     * We then call {@link #dispose}.
     */
    @SuppressWarnings({"FinalizeDeclaration", "deprecation"})
    @Override
    protected void finalize() {
        dispose();
    }

}
