package com.hardbacknutter.sshclient.channels.session;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.ChannelExec;
import com.hardbacknutter.sshclient.channels.SshChannelException;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.transport.SessionImpl;
import com.hardbacknutter.sshclient.utils.SshConstants;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/**
 * A channel to execute a command on the remote.
 * <p>
 * "want reply" is set to {@code false}
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.5">
 * RFC 4254 SSH Connection Protocol, section 6.5. Starting a Shell or a Command</a>
 */
public class ChannelExecImpl
        extends ChannelSessionImpl
        implements ChannelExec {

    private static final byte[] REQUEST = ChannelExec.NAME.getBytes(StandardCharsets.UTF_8);

    @NonNull
    private String command = "";
    private boolean waitForReply;

    public ChannelExecImpl(@NonNull final SessionImpl session) {
        super(session);
    }

    public void setWaitForReply(final boolean waitForReply) {
        this.waitForReply = waitForReply;
    }

    /**
     * Set the command to be executed.
     *
     * @param command the command to be executed
     */
    @Override
    public void setCommand(@NonNull final String command) {
        this.command = command;
    }

    @Override
    protected void onAfterConnect(@NonNull final SessionImpl session)
            throws GeneralSecurityException, IOException, SshChannelException {

        sendSessionRequests();

        // byte      SSH_MSG_CHANNEL_REQUEST
        // uint32    recipient channel
        // string    "exec"
        // boolean   want reply
        // string    command
        sendRequest((recipient, wantReply) -> new Packet(SshConstants.SSH_MSG_CHANNEL_REQUEST)
                            .putInt(recipient)
                            .putString(REQUEST)
                            .putBoolean(wantReply)
                            .putString(command),
                    this.waitForReply);

        if (ioStreams.hasInputStream()) {
            startThread();
        }
    }
}
