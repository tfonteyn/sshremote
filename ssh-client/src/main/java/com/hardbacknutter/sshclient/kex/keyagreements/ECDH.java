package com.hardbacknutter.sshclient.kex.keyagreements;

import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;

import com.hardbacknutter.sshclient.SshClient;
import com.hardbacknutter.sshclient.kex.KexProposal;
import com.hardbacknutter.sshclient.keypair.ECKeyType;

import org.jspecify.annotations.NonNull;

/**
 * An interface with the mathematical operations needed for
 * the Elliptic Curve Diffie-Hellman key exchanges.
 * <p>
 * The implementing class will be chosen by the
 * {@linkplain SshClient#setConfig configuration option} {@link KexProposal#KEY_AGREEMENT_ECDH}.
 */
public interface ECDH {

    /**
     * Initialises this instance for key pairs using the specified curve.
     *
     * @param ecKeyType {@link ECKeyType}
     *
     * @throws GeneralSecurityException if anything goes wrong.
     */
    void init(@NonNull ECKeyType ecKeyType)
            throws GeneralSecurityException;

    /**
     * Retrieves the public key (i.e. an elliptic curve point) to be sent to the remote side.
     *
     * @return Q_C, client's ephemeral public key octet string
     *
     * @throws GeneralSecurityException if anything goes wrong.
     */
    byte @NonNull [] getQ()
            throws GeneralSecurityException;

    /**
     * Get the shared secret for this key exchange.
     *
     * @param w the point of the server's ephemeral public key
     *
     * @return the shared secret K, in the form of a byte[].
     *
     * @throws GeneralSecurityException if anything goes wrong.
     */
    byte @NonNull [] getSharedSecret(@NonNull ECPoint w)
            throws GeneralSecurityException;


    /**
     * Validates a public key (i.e. an elliptic curve point) sent by the remote side.
     *
     * @param w the point of the server's ephemeral public key
     *
     * @throws GeneralSecurityException if anything goes wrong.
     */
    void validate(@NonNull ECPoint w)
            throws GeneralSecurityException;
}
