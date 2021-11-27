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
package com.hardbackcollector.sshclient.identity;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.SshClient;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * A user identity for public-key authentication.
 * This object encapsulates a key pair and the signature algorithm.
 * It is used by the Session objects on connecting to authenticate
 * to the server.
 *
 * @see SshClient#addIdentity(Identity, byte[])
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4252#section-7">
 * RFC 4252 SSH Authentication Protocol,
 * section 7. Public Key Authentication Method: "publickey"</a>
 */
public interface Identity {

    /**
     * Get the name of this identity.
     * Information/display purposes only.
     *
     * @return the name of this identity
     */
    @NonNull
    String getName();

    /**
     * Checks whether the private key is encrypted.
     *
     * @return {@code true} if the key is encrypted,
     * i.e. a call to {@link #decrypt} is needed,
     * {@code false} if the key is ready to be used
     * (e.g. {@link #getSignature(byte[], String)} can be called).
     */
    boolean isEncrypted();

    /**
     * Provides a passphrase to decrypt the private key.
     *
     * @return {@code true} if the passphrase was right and
     * {@link #getSignature(byte[], String)} can now be used,
     * {@code false} if the passphrase was wrong.
     */
    boolean decrypt(@Nullable byte[] passphrase)
            throws GeneralSecurityException, IOException;

    /**
     * Returns the public key data.
     *
     * @return encoded public key
     */
    @Nullable
    byte[] getPublicKeyBlob()
            throws GeneralSecurityException;

    /**
     * Signs the given data with our private key and the given signature algorithm.
     *
     * @param data      data to be signed
     * @param algorithm signature algorithm to use
     * @return a signature of {@code data}
     */
    @NonNull
    byte[] getSignature(@NonNull byte[] data,
                        @NonNull String algorithm)
            throws GeneralSecurityException;

    /**
     * Returns the name of the algorithm. This will be sent together with
     * the public key to the server for authorization purposes. The server
     * will use the signature checking algorithm to check the signature.
     *
     * @return "ssh-rsa", "ssh-dss", "ecdsa-sha2-*", "ssh-ed25519"
     */
    @NonNull
    String getHostKeyAlgorithm()
            throws GeneralSecurityException;

    /**
     * Disposes internally allocated data, like byte array for the private key.
     * This will be called by the library when the identity is removed.
     */
    void clear();
}
