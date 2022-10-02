package com.hardbacknutter.sshclient.kex.keyagreements;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.SshClient;
import com.hardbacknutter.sshclient.kex.KexProposal;

import java.math.BigInteger;
import java.security.GeneralSecurityException;

/**
 * An interface with the mathematical operations needed for
 * the Diffie-Hellman key exchanges.
 * <p>
 * The implementing class will be chosen by the
 * {@linkplain SshClient#setConfig configuration option} {@link KexProposal#KEY_AGREEMENT_DH}.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-8">
 * RFC 4253 SSH Transport Layer Protocol, section 8. Diffie-Hellman Key Exchange</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4419">
 * RFC 4419, Diffie-Hellman Group Exchange for the SSH Transport Layer Protocol</a>
 */
public interface DH {

    /**
     * initializes the algorithm object for a new exchange.
     */
    void init()
            throws GeneralSecurityException;

    /**
     * Sets the prime number (modulus) with which the calculations should be done.
     */
    void setP(@NonNull BigInteger p);

    /**
     * Sets the generator of the group.
     * (This will be most often be {@code 2} or another small prime.)
     */
    void setG(@NonNull BigInteger g);

    /**
     * Calculate the Public value to send to the server.
     * This is the value {@code e}, which is the result of {@code g^x mod P}.
     * <p>
     * WARNING: implementation CAN/will recalculate each time this method is called.
     * It should only be called ONCE after a {@link #setP} + {@link #setG} call.
     */
    @NonNull
    BigInteger getE()
            throws GeneralSecurityException;

    /**
     * Get the shared secret for this key exchange.
     *
     * @return the shared secret K, in the form of a byte[].
     */
    @NonNull
    byte[] getSharedSecret(@NonNull BigInteger f)
            throws GeneralSecurityException;

    /**
     * Validates a public key
     *
     * @param e client challenge
     * @param f server response value
     */
    void validate(@NonNull BigInteger e,
                  @NonNull BigInteger f)
            throws GeneralSecurityException;
}
