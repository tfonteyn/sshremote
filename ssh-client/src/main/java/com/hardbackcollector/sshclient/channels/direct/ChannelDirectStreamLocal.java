package com.hardbackcollector.sshclient.channels.direct;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.Logger;
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
            if (session.getLogger().isEnabled(Logger.FATAL)) {
                session.getLogger().log(Logger.FATAL, () -> ERROR_SOCKET_PATH_MUST_BE_SET);
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
