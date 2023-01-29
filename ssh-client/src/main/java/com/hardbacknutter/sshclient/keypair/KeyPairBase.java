package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.SshClientConfig;
import com.hardbacknutter.sshclient.hostkey.HostKey;
import com.hardbacknutter.sshclient.identity.Identity;
import com.hardbacknutter.sshclient.identity.IdentityImpl;
import com.hardbacknutter.sshclient.utils.Buffer;

import java.io.IOException;
import java.security.GeneralSecurityException;

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
    @NonNull
    PrivateKeyBlob privateKeyBlob;
    /**
     * The encoded public key; if we have it, we use it directly, otherwise it will be
     * build from the key components.
     */
    @Nullable
    byte[] publicKeyBlob;
    @NonNull
    String publicKeyComment = "";

    /**
     * Constructor.
     */
    KeyPairBase(@NonNull final SshClientConfig config) {
        this.config = config;
        this.privateKeyBlob = new PrivateKeyBlob();
    }

    /**
     * Constructor.
     */
    KeyPairBase(@NonNull final SshClientConfig config,
                @NonNull final PrivateKeyBlob privateKeyBlob) {
        this.config = config;
        this.privateKeyBlob = privateKeyBlob;
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
        final Buffer buffer = new Buffer((2 * 4)
                                                 + signature_name.length()
                                                 + signature_blob.length)
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
        return privateKeyBlob.isEncrypted();
    }

    /**
     * TRY to parse the <strong>unencrypted</strong> but encoded key blob.
     * <p>
     * This is a NOP if either the key blob or the format was {@code null}.
     *
     * @throws GeneralSecurityException if the key <strong>could</strong> be parsed but was invalid.
     */
    void parse()
            throws GeneralSecurityException {
        final byte[] blob = privateKeyBlob.getBlob();
        final Vendor format = privateKeyBlob.getFormat();
        if (blob != null && format != null) {
            parse(blob, format);
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
        if (!privateKeyBlob.isEncrypted()) {
            return true;
        }

        final Vendor format = privateKeyBlob.getFormat();
        // sanity check
        if (format == null) {
            return false;
        }

        // decrypted key, or garbage!
        final byte[] plainKey = privateKeyBlob.decrypt(passphrase);
        // We MUST try parsing first to determine if it decrypted ok, or not!
        parse(plainKey, format);

        if (privateKeyBlob.isEncrypted()) {
            // still encrypted or perhaps garbage
            return false;
        }

        // success, replace the encrypted key with the now plain key
        privateKeyBlob.setBlob(plainKey);
        return true;
    }

    @Override
    @NonNull
    public String toString() {
        return "KeyPairBase{" +
                "privateKeyBlob=" + privateKeyBlob +
                // ", publicKeyBlob=" + publicKeyBlob +
                ", publicKeyComment='" + publicKeyComment + '\'' +
                "}";
    }

    @Override
    public void dispose() {
        privateKeyBlob.dispose();
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
