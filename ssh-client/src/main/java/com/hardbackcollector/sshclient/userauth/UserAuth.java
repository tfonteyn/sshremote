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
package com.hardbackcollector.sshclient.userauth;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.Session;
import com.hardbackcollector.sshclient.SshClientConfig;
import com.hardbackcollector.sshclient.transport.PacketIO;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4252">
 * RFC 4252 SSH Authentication Protocol </a>
 */
public interface UserAuth {

    /**
     * Service name to request authentication.
     */
    String SSH_USERAUTH = "ssh-userauth";
    /**
     * Service name to connect/authenticate.
     */
    String SSH_CONNECTION = "ssh-connection";

    void init(@NonNull SshClientConfig config,
              @NonNull String username,
              @Nullable UserInfo userinfo)
            throws NoSuchAlgorithmException;

    /**
     * Will be called by the Session to do the authentication.
     * Subclasses will implement this method and do the actual
     * authentication, using the {@link PacketIO}'s read/write methods.
     *
     * @param password as set on the session, which might be {@code null}.
     * @return {@code true} if the authentication was successful, else {@code false}.
     * @throws SshPartialAuthException        if the authentication was partially
     *                                        successful, i.e. not yet sufficient to login,
     *                                        but enough to continue with more methods.
     * @throws SshAuthCancelException         if the authentication was deliberately cancelled
     * @throws SshTooManyAuthAttemptException if a method was tried to many times
     * @throws IOException                    on communication with the server problems
     */
    boolean authenticate(@NonNull Session session,
                         @NonNull PacketIO io,
                         @Nullable byte[] password)
            throws IOException, GeneralSecurityException, SshAuthException;
}
