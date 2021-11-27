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
package com.hardbackcollector.sshclient.forwarding;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.channels.direct.ChannelDirectTCPIP;
import com.hardbackcollector.sshclient.transport.SessionImpl;

import java.net.Socket;
import java.util.Objects;

import javax.net.ServerSocketFactory;

/**
 * Takes care of forwarding a local port to the remote
 */
class LocalPortForwardWorker
        extends LocalForwardWorker {

    @Nullable
    private String host;
    private int remotePort = -1;

    LocalPortForwardWorker(@NonNull final SessionImpl session,
                           @Nullable final String address,
                           final int localPort,
                           final int connectTimeout,
                           @Nullable final ServerSocketFactory ssf) {
        super(session, address, localPort, connectTimeout, ssf);
    }

    @Nullable
    String getHost() {
        return host;
    }

    int getRemotePort() {
        return remotePort;
    }

    void setRemote(@NonNull final String remoteHost,
                   final int remotePort) {
        this.host = remoteHost;
        this.remotePort = remotePort;
    }

    public void run() {
        try {
            while (thread != null) {
                // accept() blocks until a connection is made.
                final Socket socket = ss.accept();
                socket.setTcpNoDelay(true);

                Objects.requireNonNull(host);

                final ChannelDirectTCPIP channel = new ChannelDirectTCPIP(session);

                channel.setHost(host);
                channel.setPort(remotePort);
                channel.setOriginatorIPAddress(socket.getInetAddress().getHostAddress());
                channel.setOriginatorPort(socket.getPort());

                channel.setInputStream(socket.getInputStream());
                channel.setOutputStream(socket.getOutputStream());
                channel.connect(connectTimeout);
            }
        } catch (final Exception ignore) {
        }
        close();
    }
}
