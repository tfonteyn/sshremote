package com.hardbacknutter.sshclient.keypair;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbacknutter.sshclient.identity.Identity;
import com.hardbacknutter.sshclient.signature.SshSignature;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

public interface SshKeyPair {

    /**
     * Return the SSH name for the host-key algorithm used.
     *
     * @return "ssh-dss", "ssh-rsa", "ecdsa*", "ssh-ed25519", "ssh-ed448"
     */
    @NonNull
    String getHostKeyAlgorithm()
            throws GeneralSecurityException;

    int getKeySize();

    /**
     * Returns the blob of the public key in the <strong>SSH wrapped encoding</strong>.
     * <p>
     * string    format identifier
     * byte[n]   key data
     *
     * @return blob of the public key
     */
    @NonNull
    byte[] getSshEncodedPublicKey();

    @NonNull
    PublicKey getPublicKey()
            throws InvalidKeySpecException,
                   InvalidParameterSpecException,
                   NoSuchAlgorithmException,
                   NoSuchProviderException;

    /**
     * Returns the user comment of the public key.
     * Will be {@code ""} if not set.
     *
     * @return comment as set, or the empty string
     */
    @NonNull
    String getPublicKeyComment();

    void setPublicKeyComment(@Nullable String comment);

    /**
     * Check whether the private key is currently encrypted.
     *
     * @return {@code true} if the private key is encrypted,
     * {@code false} if not.
     */
    boolean isEncrypted();

    /**
     * Decrypts the private key, using a passphrase.
     *
     * @return {@code true} if the private key was successfully
     * decrypted, i.e. is now usable, else {@code false}.
     */
    boolean decrypt(@Nullable byte[] passphrase)
            throws GeneralSecurityException, IOException;

    /**
     * Sign the data with the given algorithm.
     *
     * @param data to sign
     *
     * @return the SSH wrapped signature.
     *
     * @see #getSignature(byte[], String)
     */
    @NonNull
    default byte[] getSignature(@NonNull final byte[] data)
            throws GeneralSecurityException {
        return getSignature(data, getHostKeyAlgorithm());
    }

    /**
     * Sign the data with the given algorithm.
     *
     * <pre>
     * Signatures are encoded as follows:
     *       string    signature format identifier (as specified by the
     *                 public key/certificate format)
     *       byte[n]   signature blob in format specific encoding.
     * </pre>
     *
     * @param data      to sign
     * @param algorithm the ssh style signature algorithm name
     *
     * @return the SSH wrapped signature.
     */
    @NonNull
    byte[] getSignature(@NonNull byte[] data,
                        @NonNull String algorithm)
            throws GeneralSecurityException;

    /**
     * Not used by the library.
     *
     * @return the verifier to verify data returned by {@link #getSignature(byte[])}
     */
    @NonNull
    SshSignature getVerifier()
            throws GeneralSecurityException, IOException;

    /**
     * Creates and returns a fingerprint of the public key,
     * i.e. the hexadecimal representation of the hash of the public key.
     * <p>
     * Uses the on the client or session configured hash algorithm.
     */
    @NonNull
    String getFingerPrint()
            throws NoSuchAlgorithmException;

    /**
     * Creates and returns a fingerprint of the public key,
     * i.e. the hexadecimal representation of the hash of the public key.
     * <p>
     * Uses the specified hash algorithm.
     */
    @NonNull
    String getFingerPrint(@NonNull String algorithm)
            throws NoSuchAlgorithmException;

    /**
     * Convert this KeyPair to the binary format for the SSH agent.
     *
     * @return blob of the key pair
     */
    @NonNull
    byte[] toSshAgentEncodedKeyPair()
            throws GeneralSecurityException;

    /**
     * Create an {@link Identity} from this key pair with the given name.
     *
     * @param name to use for the identity
     *
     * @return new identity instance
     */
    @NonNull
    Identity toIdentity(@NonNull String name)
            throws GeneralSecurityException;

    /**
     * Disposes this key pair. This should throw away all private key material
     * and the passphrase.
     */
    void dispose();
}
