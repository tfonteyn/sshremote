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

import com.hardbackcollector.sshclient.Session;
import com.hardbackcollector.sshclient.transport.Packet;
import com.hardbackcollector.sshclient.transport.SessionImpl;
import com.hardbackcollector.sshclient.utils.SshConstants;

/**
 * A Channel which allows forwarding a pair of local streams
 * to/from a TCP-connection to a server on the remote side.
 *
 * @see Session#openChannel Session.openChannel("direct-tcpip")
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-7.2">
 * RFC 4254 SSH Connection Protocol, section 7.2. TCP/IP Forwarding Channels</a>
 */
public class ChannelDirectTCPIP
        extends ChannelDirect {

    public static final String NAME = "direct-tcpip";

    @NonNull
    private String originatorIpAddress = "127.0.0.1";
    private int originatorPort;

    private String host;
    private int port;

    public ChannelDirectTCPIP(@NonNull final SessionImpl session) {
        super(NAME, session);
    }

    /**
     * Sets the remote host name (or IP address) to connect to
     * (which should be valid at the remote side).
     * <p>
     * This should be called before {@link #connect}.
     *
     * @see #setPort
     */
    public void setHost(@NonNull final String host) {
        this.host = host;
    }

    /**
     * Sets the remote port number to connect to.
     * <p>
     * This should be called before {@link #connect}.
     *
     * @see #setHost
     */
    public void setPort(final int port) {
        this.port = port;
    }

    /**
     * Sets the local originator IP address we pretend the connection
     * came from. The default value is {@code "127.0.0.1"}.
     * <p>
     * This should be called before {@link #connect}.
     *
     * @see #setOriginatorPort
     */
    public void setOriginatorIPAddress(@NonNull final String ipAddress) {
        this.originatorIpAddress = ipAddress;
    }

    /**
     * Sets the local originator port number we pretend the connection
     * came from. The default value is {@code 0}.
     * <p>
     * This should be called before {@link #connect}.
     *
     * @see #setOriginatorIPAddress
     */
    public void setOriginatorPort(final int port) {
        this.originatorPort = port;
    }

    @Override
    @NonNull
    protected Packet createChannelOpenPacket() {
        // byte   SSH_MSG_CHANNEL_OPEN
        // string channel type
        // uint32 sender channel
        // uint32 initial window size
        // uint32 maximum packet size
        //
        // string    host to connect
        // uint32    port to connect
        // string    originator IP address
        // uint32    originator port
        return new Packet(SshConstants.SSH_MSG_CHANNEL_OPEN)
                .putString(getType())
                .putInt(getId())
                .putInt(localWindowSize)
                .putInt(localMaxPacketSize)

                .putString(host)
                .putInt(port)
                .putString(originatorIpAddress)
                .putInt(originatorPort);
    }
}
