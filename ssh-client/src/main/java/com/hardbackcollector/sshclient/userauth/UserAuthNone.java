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

import com.hardbackcollector.sshclient.Logger;
import com.hardbackcollector.sshclient.Session;
import com.hardbackcollector.sshclient.SshClient;
import com.hardbackcollector.sshclient.SshClientConfig;
import com.hardbackcollector.sshclient.transport.Packet;
import com.hardbackcollector.sshclient.transport.PacketIO;
import com.hardbackcollector.sshclient.utils.SshConstants;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4252#section-5.2">
 * RFC 4252 SSH Authentication Protocol,
 * section 5.2. The "none" Authentication Request</a>
 */
public class UserAuthNone
        implements UserAuth {

    public static final String METHOD = "none";

    private String methods;

    private String username;
    @Nullable
    private UserInfo userinfo;


    @Override
    public void init(@NonNull final SshClientConfig config,
                     @NonNull final String username,
                     @Nullable final UserInfo userinfo) {
        this.username = username;
        this.userinfo = userinfo;
    }

    @Override
    public boolean authenticate(@NonNull final Session session,
                                @NonNull final PacketIO io,
                                @Nullable final byte[] password)
            throws IOException, GeneralSecurityException, SshAuthException {

        // send
        // byte      SSH_MSG_SERVICE_REQUEST(5)
        // string    service name "ssh-userauth"
        Packet packet = new Packet(SshConstants.SSH_MSG_SERVICE_REQUEST)
                .putString(UserAuth.SSH_USERAUTH);
        io.write(packet);

        if (SshClient.getLogger().isEnabled(Logger.DEBUG)) {
            SshClient.getLogger().log(Logger.DEBUG, "SSH_MSG_SERVICE_REQUEST sent");
        }

        // receive
        // byte      SSH_MSG_SERVICE_ACCEPT(6)
        // string    service name
        packet = io.read();
        final boolean serviceAccepted =
                (packet.getCommand() == SshConstants.SSH_MSG_SERVICE_ACCEPT);

        if (SshClient.getLogger().isEnabled(Logger.DEBUG)) {
            SshClient.getLogger().log(Logger.DEBUG, "SSH_MSG_SERVICE_ACCEPT received;"
                    + " serviceAccepted: " + serviceAccepted);
        }

        if (!serviceAccepted) {
            return false;
        }

        // byte      SSH_MSG_USERAUTH_REQUEST(50)
        // string    user name
        // string    service name ("ssh-connection")
        // string    method ("none")
        packet.startCommand(SshConstants.SSH_MSG_USERAUTH_REQUEST)
                .putString(username)
                .putString(UserAuth.SSH_CONNECTION)
                .putString(METHOD);
        io.write(packet);

        while (true) {
            packet = io.read();
            final byte command = packet.getCommand();

            if (command == SshConstants.SSH_MSG_USERAUTH_SUCCESS) {
                return true;

            } else if (command == SshConstants.SSH_MSG_USERAUTH_FAILURE) {
                packet.startReadingPayload();
                packet.getByte(); // command
                methods = packet.getJString();
                packet.getBoolean(); // partial_success
                return false;

            } else if (command == SshConstants.SSH_MSG_USERAUTH_BANNER) {
                if (userinfo != null) {
                    packet.startReadingPayload();
                    packet.getByte(); // command
                    final String message = packet.getJString();
                    packet.skipString(/* language_tag */);

                    userinfo.showMessage(message);
                }
            } else {
                throw new SshAuthException("UserAuthNone fail (" + command + ")");
            }
        }
    }

    /**
     * @return list of auth methods supported by the server
     */
    @NonNull
    public List<String> getMethods() {
        if (methods == null) {
            return new ArrayList<>();
        }

        return Arrays.asList(methods.split(","));
    }
}
