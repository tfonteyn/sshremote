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
package com.hardbackcollector.sshclient.macs;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.kex.KexProposal;

import java.security.GeneralSecurityException;

/**
 * A Keyed-Hashing algorithm for Message Authentication which will be used
 * to make sure the messages are not tampered with.
 * <p>
 * Similar to a MessageDigest, a Message Authentication Code (MAC) provides a way
 * to check the integrity of information transmitted over or stored in an unreliable
 * medium, but includes a secret key in the calculation.
 * <p>
 * The library gets the implementation class from a configuration option
 * (with the name of the algorithm as key) and then instantiates an object
 * using the no-argument constructor.
 * <p>
 * The algorithms to be used are negotiated during key exchange.
 * <h4>Configuration</h4>
 * <dl>
 *  <dt>{@link KexProposal#PROPOSAL_MAC_CTOS mac.c2s}</dt>
 *  <dd>message authentication code algorithms for client-to-server transport.</dd>
 *  <dt>{@link KexProposal#PROPOSAL_MAC_CTOS mac.s2c}</dt>
 *  <dd>message authentication code algorithms for server-to-client transport.</dd>
 * </dl>
 * <p>
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4253#section-6.4">
 * RFC 4253 SSH Transport Layer Protocol, Section 6.4. Data Integrity</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6668#section-2>
 * RFC 6668 SHA-2 Data Integrity Verification for the SSH Transport Layer Protocol,
 * Section 2. Data Integrity</a>
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2104">
 * RFC 2104 HMAC: Keyed-Hashing for Message Authentication</a>
 * @see javax.crypto.Mac
 */
public interface SshMac {

    /**
     * Get the digest length of the Mac.
     * Depending on which docs you read (Java, SSH, Wiki...),
     * this is also known as also known as <em>hash-size</em></em>
     * and as <em>hash output length</em>
     * <p>
     * Not to be confused with the key-block-length.
     *
     * @return size in bytes
     */
    int getDigestLength();

    /**
     * Indicates if a MAC is of the EtM type.
     * Encrypt-then-MAC (EtM)
     */
    boolean isEtm();

    /**
     * Initializes the MAC, providing the key.
     */
    void init(@NonNull byte[] key)
            throws GeneralSecurityException;

    /**
     * Updates the MAC with 4 bytes of data.
     *
     * @param seq a 32 bit value, which will be interpreted as 4 bytes in big-endian order.
     */
    void update(int seq);

    /**
     * Updates the MAC with some data.
     *
     * @param input  an array containing the data to authenticate.
     * @param offset the position in {@code foo} where the data starts.
     * @param len    the length of the data.
     */
    void update(@NonNull byte[] input,
                int offset,
                int len);

    /**
     * Finalizes the production of the digest, producing the digest value.
     *
     * @param output    an array to put the authentication code into.
     * @param outOffset the position in {@code output} where the output should begin.
     */
    void doFinal(@NonNull byte[] output,
                 int outOffset)
            throws GeneralSecurityException;
}
