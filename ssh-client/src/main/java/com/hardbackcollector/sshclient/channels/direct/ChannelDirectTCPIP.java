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
