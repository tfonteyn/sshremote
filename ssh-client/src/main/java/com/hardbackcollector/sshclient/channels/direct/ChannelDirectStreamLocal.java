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
package com.hardbackcollector.sshclient.channels.direct;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.Logger;
import com.hardbackcollector.sshclient.SshClient;
import com.hardbackcollector.sshclient.transport.Packet;
import com.hardbackcollector.sshclient.transport.SessionImpl;
import com.hardbackcollector.sshclient.utils.SshConstants;

/**
 * A Channel which allows forwarding a socket-path.
 *
 * @see <a href="https://github.com/openssh/openssh-portable/blob/master/PROTOCOL">
 * openssh-portable/PROTOCOL: 2.4. connection: Unix domain socket forwarding</a>
 * @see <a href="http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL?rev=HEAD">
 * OpenBSD protocol source</a>
 */
public class ChannelDirectStreamLocal
        extends ChannelDirect {

    public static final String NAME = "direct-streamlocal@openssh.com";

    private static final String ERROR_SOCKET_PATH_MUST_BE_SET = "socketPath must be set";

    @Nullable
    private String socketPath;

    public ChannelDirectStreamLocal(@NonNull final SessionImpl session) {
        super(NAME, session);
    }

    public void setSocketPath(@NonNull final String socketPath) {
        this.socketPath = socketPath;
    }

    @Override
    @NonNull
    protected Packet createChannelOpenPacket() {

        if (socketPath == null) {
            if (SshClient.getLogger().isEnabled(Logger.FATAL)) {
                SshClient.getLogger().log(Logger.FATAL, ERROR_SOCKET_PATH_MUST_BE_SET);
            }
            throw new IllegalStateException(ERROR_SOCKET_PATH_MUST_BE_SET);
        }

        /*
        Similar to direct-tcpip, direct-streamlocal is sent by the client
        to request that the server make a connection to a Unix domain socket.

            byte		SSH_MSG_CHANNEL_OPEN
            string		"direct-streamlocal@openssh.com"
            uint32		sender channel
            uint32		initial window size
            uint32		maximum packet size

            string		socket path
            string		reserved
            uint32		reserved
         */
        return new Packet(SshConstants.SSH_MSG_CHANNEL_OPEN)
                .putString(getType())
                .putInt(getId())
                .putInt(localWindowSize)
                .putInt(localMaxPacketSize)

                .putString(socketPath)
                .putString("")
                .putInt(0);
    }
}
