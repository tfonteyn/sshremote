/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2015-2018 ymnk, JCraft,Inc. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in
     the documentation and/or other materials provided with the distribution.

  3. The names of the authors may not be used to endorse or promote products
     derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL JCRAFT,
INC. OR ANY CONTRIBUTORS TO THIS SOFTWARE BE LIABLE FOR ANY DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
package com.hardbackcollector.sshclient.kex.keyagreements;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.SshClient;
import com.hardbackcollector.sshclient.kex.KexProposal;
import com.hardbackcollector.sshclient.keypair.ECKeyType;

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
     * @throws GeneralSecurityException if anything goes wrong.
     */
    void init(@NonNull final ECKeyType ecType)
            throws GeneralSecurityException;

    /**
     * Retrieves the public key (i.e. an elliptic curve point) to be sent to the remote side.
     *
     * @return Q_C, client's ephemeral public key octet string
     * @throws GeneralSecurityException if anything goes wrong.
     */
    @NonNull
    byte[] getQ()
            throws GeneralSecurityException;

    /**
     * Get the shared secret for this key exchange.
     *
     * @param w the point of the server's ephemeral public key
     * @return the shared secret K, in the form of a byte[].
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
