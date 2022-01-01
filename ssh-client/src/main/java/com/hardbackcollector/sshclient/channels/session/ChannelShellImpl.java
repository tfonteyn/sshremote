package com.hardbackcollector.sshclient.channels.session;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.ChannelShell;
import com.hardbackcollector.sshclient.channels.SshChannelException;
import com.hardbackcollector.sshclient.transport.Packet;
import com.hardbackcollector.sshclient.transport.SessionImpl;
import com.hardbackcollector.sshclient.utils.SshConstants;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/**
 * A channel connected to a remote shell.
 * <p>
 * "want reply" is set to {@code true}
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.5">
 * RFC 4254 SSH Connection Protocol, section 6.5. Starting a Shell or a Command</a>
 */
public class ChannelShellImpl
        extends ChannelSessionImpl
        implements ChannelShell {

    private static final byte[] REQUEST = ChannelShell.NAME.getBytes(StandardCharsets.UTF_8);

    private boolean waitForReply = true;

    public ChannelShellImpl(@NonNull final SessionImpl session) {
        super(session);
    }

    public void setWaitForReply(final boolean waitForReply) {
        this.waitForReply = waitForReply;
    }

    @Override
    protected void onAfterConnect(@NonNull final SessionImpl session)
            throws SshChannelException, GeneralSecurityException, IOException {

        setPty(true);
        sendSessionRequests();

        // byte      SSH_MSG_CHANNEL_REQUEST
        // uint32    recipient channel
        // string    "shell"
        // boolean   want reply
        sendRequest((recipient, wantReply) -> new Packet(SshConstants.SSH_MSG_CHANNEL_REQUEST)
                            .putInt(recipient)
                            .putString(REQUEST)
                            .putBoolean(wantReply),
                    waitForReply);

        if (ioStreams.hasInputStream()) {
            startThread();
        }
    }
}
