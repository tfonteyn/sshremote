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

import com.hardbackcollector.sshclient.SshClientConfig;
import com.hardbackcollector.sshclient.keypair.SshKeyPair;
import com.hardbackcollector.sshclient.keypair.util.KeyPairTool;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * The default (internal) Identity implementation.
 */
public final class IdentityImpl
        implements Identity {

    @SuppressWarnings({"FieldCanBeLocal", "unused", "FieldNotUsedInToString"})
    @NonNull
    private final SshClientConfig config;
    @NonNull
    private final String name;
    @NonNull
    private final SshKeyPair sshKeyPair;

    public IdentityImpl(@NonNull final SshClientConfig config,
                        @NonNull final String name,
                        @NonNull final SshKeyPair sshKeyPair) {
        this.config = config;
        this.name = name;
        this.sshKeyPair = sshKeyPair;
    }

    /**
     * Creates a new Identity from the public and private key file names.
     */
    @NonNull
    public static Identity fromFiles(@NonNull final SshClientConfig config,
                                     @NonNull final String prvKeyFilename,
                                     @Nullable final String pubKeyFilename)
            throws IOException, GeneralSecurityException {

        final KeyPairTool keyPairTool = new KeyPairTool(config);
        final SshKeyPair keyPair = keyPairTool.load(prvKeyFilename, pubKeyFilename);
        return new IdentityImpl(config, prvKeyFilename, keyPair);
    }

    /**
     * Creates a new Identity from the public and private key data.
     * The private key array will be zeroed out after reading.
     */
    @NonNull
    public static Identity fromKeyData(@NonNull final SshClientConfig config,
                                       @NonNull final String name,
                                       @NonNull final byte[] prvKey,
                                       @Nullable final byte[] pubKey)
            throws IOException, GeneralSecurityException {

        final KeyPairTool keyPairTool = new KeyPairTool(config);
        final SshKeyPair keyPair = keyPairTool.load(prvKey, pubKey);
        return new IdentityImpl(config, name, keyPair);
    }

    /**
     * Decrypts this identity with the specified pass-phrase.
     *
     * @param passphrase the pass-phrase for this identity.
     *                   a {@code null} is valid input as the identity CAN be unencrypted
     * @return {@code true} if the decryption has succeeded
     * or if this identity is not encrypted.
     */
    @Override
    public boolean decrypt(@Nullable final byte[] passphrase)
            throws GeneralSecurityException, IOException {
        return sshKeyPair.decryptPrivateKey(passphrase);
    }

    /**
     * Returns the public-key blob.
     *
     * @return the public-key blob
     */
    @Override
    @Nullable
    public byte[] getPublicKeyBlob()
            throws GeneralSecurityException {
        return sshKeyPair.getSshPublicKeyBlob();
    }

    @Override
    @NonNull
    public byte[] getSignature(@NonNull final byte[] data,
                               @NonNull final String algorithm)
            throws GeneralSecurityException {
        return sshKeyPair.getSignature(data, algorithm);
    }

    /**
     * Returns the name of the key algorithm.
     *
     * @return "ssh-rsa", "ssh-dss", "ecdsa-sha2-*", "ssh-ed25519" etc...
     */
    @Override
    @NonNull
    public String getHostKeyAlgorithm()
            throws GeneralSecurityException {
        return sshKeyPair.getHostKeyAlgorithm();
    }

    /**
     * Returns the name of this identity.
     * It will be useful to identify this object in the {@link IdentityRepository}.
     */
    @Override
    @NonNull
    public String getName() {
        return name;
    }

    /**
     * Returns {@code true} if this identity is encrypted.
     *
     * @return {@code true} if this identity is encrypted.
     */
    @Override
    public boolean isEncrypted() {
        return sshKeyPair.isPrivateKeyEncrypted();
    }

    /**
     * Disposes internally allocated data, like byte array for the private key.
     */
    @Override
    public void clear() {
        sshKeyPair.dispose();
    }

    @Override
    @NonNull
    public String toString() {
        return "IdentityFile{" +
                "identity='" + name + '\'' +
                ", sshKeyPair=" + sshKeyPair +
                '}';
    }
}
