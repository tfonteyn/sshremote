package com.hardbacknutter.sshclient.signature;

import androidx.annotation.NonNull;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * A generic signature algorithm, with key and some state of
 * an ongoing signing or verification algorithm.
 */
public interface SshSignature {

    /**
     * Initializes the signature object. (This can only do initialization
     * which does not depend on whether signing or verifying is done.)
     *
     * @param algorithm for signing/verifying.
     */
    void init(@NonNull String algorithm)
            throws GeneralSecurityException;

    /**
     * Add more data to be signed/verified.
     *
     * @param data the array containing the data to be signed/verified.
     */
    void update(@NonNull byte[] data)
            throws GeneralSecurityException;

    /**
     * Sets the private key to be used for signing.
     */
    void initSign(@NonNull PrivateKey key)
            throws GeneralSecurityException;

    /**
     * Signs the data given so far to the {@link #update} method.
     *
     * @return a signature for the data.
     */
    @NonNull
    byte[] sign()
            throws GeneralSecurityException;

    /**
     * Sets the public key to be used for signature verification.
     */
    void initVerify(@NonNull PublicKey key)
            throws GeneralSecurityException;

    /**
     * Verifies that the given signature is a correct signature.
     * <p>
     * Implementations <strong>MUST</strong> accept an ssh style wrapped signature blob,
     * or a raw signature blob.
     *
     * @param sig an array containing the signature for the data
     *            given by {@link #update}.
     *
     * @return {@code true} if the signature is correct,
     * {@code false} if the signature is not correct.
     */
    boolean verify(@NonNull byte[] sig)
            throws GeneralSecurityException;

}
