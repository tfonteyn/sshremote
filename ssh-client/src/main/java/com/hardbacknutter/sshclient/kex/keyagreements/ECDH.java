package com.hardbacknutter.sshclient.kex.keyagreements;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.SshClient;
import com.hardbacknutter.sshclient.kex.KexProposal;
import com.hardbacknutter.sshclient.keypair.ECKeyType;

import java.security.GeneralSecurityException;
import java.security.spec.ECPoint;

/**
 * An interface with the mathematical operations needed for
 * the Elliptic Curve Diffie-Hellman key exchanges.
 * <p>
 * The implementing class will be chosen by the
 * {@linkplain SshClient#setConfig configuration option} {@link KexProposal#KEY_AGREEMENT_ECDH}.
 */
public interface ECDH {

    /**
     * Initializes this instance for key pairs using the specified curve.
     *
     * @param ecType {@link ECKeyType}
     *
     * @throws GeneralSecurityException if anything goes wrong.
     */
    void init(@NonNull final ECKeyType ecType)
            throws GeneralSecurityException;

    /**
     * Retrieves the public key (i.e. an elliptic curve point) to be sent to the remote side.
     *
     * @return Q_C, client's ephemeral public key octet string
     *
     * @throws GeneralSecurityException if anything goes wrong.
     */
    @NonNull
    byte[] getQ()
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
    @NonNull
    byte[] getSharedSecret(@NonNull ECPoint w)
            throws GeneralSecurityException;


    /**
     * Validates a public key (i.e. an elliptic curve point) sent by the remote side.
     *
     * @param w the point of the server's ephemeral public key
     */
    void validate(@NonNull ECPoint w)
            throws GeneralSecurityException;
}
