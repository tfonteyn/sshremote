package com.hardbackcollector.sshclient.kex.keyagreements;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.SshClient;
import com.hardbackcollector.sshclient.kex.KexProposal;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.jcajce.spec.XDHParameterSpec;

import java.security.GeneralSecurityException;

/**
 * An interface with the mathematical operations needed for
 * the Edwards-Curve Diffie-Hellman key exchanges.
 * <p>
 * The implementing class will be chosen by the
 * {@linkplain SshClient#setConfig configuration option} {@link KexProposal#KEY_AGREEMENT_XDH}.
 */
public interface XDH {

    /**
     * Initializes this instance for key pairs using the specified curve.
     *
     * @param xdhCurveName {@link XDHParameterSpec#X25519} or
     *                     {@link XDHParameterSpec#X448}
     * @param oid          {@link EdECObjectIdentifiers#id_X25519} or
     *                     {@link EdECObjectIdentifiers#id_X448}
     * @param keySize      32 or 57
     *
     * @throws GeneralSecurityException if anything goes wrong.
     */
    void init(@NonNull String xdhCurveName,
              @NonNull final ASN1ObjectIdentifier oid,
              final int keySize)
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
     * @param q_s Q_S, server's ephemeral public key octet string
     *
     * @return the shared secret K, in the form of a byte[].
     *
     * @throws GeneralSecurityException if anything goes wrong.
     */
    @NonNull
    byte[] getSharedSecret(@NonNull byte[] q_s)
            throws GeneralSecurityException;


    /**
     * Validates a public key (i.e. an elliptic curve point) sent by the remote side.
     *
     * @param q_s Q_S, server's ephemeral public key octet string
     */
    void validate(@NonNull byte[] q_s)
            throws GeneralSecurityException;
}
