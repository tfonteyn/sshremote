/* -*-mode:java; c-basic-offset:2; indent-tabs-mode:nil -*- */
/*
Copyright (c) 2012-2018 ymnk, JCraft,Inc. All rights reserved.

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
package com.hardbackcollector.sshclient.signature;

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
     * @return {@code true} if the signature is correct,
     * {@code false} if the signature is not correct.
     */
    boolean verify(@NonNull byte[] sig)
            throws GeneralSecurityException;

}
