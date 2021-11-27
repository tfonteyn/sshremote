/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2002-2018 ymnk, JCraft,Inc. All rights reserved.

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
