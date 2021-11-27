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
package com.hardbackcollector.sshclient;

import androidx.annotation.NonNull;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 * A factory for (client) sockets.
 * This works similar to {@link javax.net.SocketFactory}, but with the
 * ability to replace/wrap the Streams without having to subclass {@link Socket}
 * <p>
 * An application may pass an implementation of this interface to
 * the Session to control the creation of outgoing Sockets for
 * port forwarding (to other hosts/ports on the local side) or for
 * the main connection to the remote host.
 *
 * @see Session#setSocketFactory
 */
public interface SocketFactory {

    /**
     * Creates a Socket connected to a given host/port.
     *
     * @param host the destination host name.
     * @param port the destination port number.
     */
    @NonNull
    Socket createSocket(@NonNull String host,
                        int port)
            throws IOException;

    @NonNull
    default Socket createSocket(@NonNull final String host,
                                final int port,
                                final int timeoutInMillis)
            throws IOException {
        return createSocket(host, port);
    }

    /**
     * Creates an InputStream for a Socket.
     * The default implementation simply calls
     * {@code return socket.getInputStream()},
     * but advanced implementations may wrap the stream.
     *
     * @param socket a socket created with {@link #createSocket}.
     * @return an InputStream reading from the socket.
     */
    @NonNull
    default InputStream getInputStream(@NonNull final Socket socket)
            throws IOException {
        return socket.getInputStream();
    }

    /**
     * Creates an OutputStream for a Socket.
     * The default implementation simply calls
     * {@code return socket.getOutputStream()},
     * but advanced implementations may wrap the stream.
     *
     * @param socket a socket created with {@link #createSocket}.
     * @return an OutputStream writing to the socket.
     */
    @NonNull
    default OutputStream getOutputStream(@NonNull final Socket socket)
            throws IOException {
        return socket.getOutputStream();
    }
}
