package com.hardbacknutter.sshclient.channels.session;

import androidx.annotation.NonNull;

import com.hardbacknutter.sshclient.ChannelSubsystem;
import com.hardbacknutter.sshclient.channels.SshChannelException;
import com.hardbacknutter.sshclient.channels.sftp.ChannelSftpImpl;
import com.hardbacknutter.sshclient.transport.Packet;
import com.hardbacknutter.sshclient.transport.SessionImpl;
import com.hardbacknutter.sshclient.utils.SshConstants;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * A skeleton class for a channel connected to a subsystem of the server process.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.5">
 * RFC 4254 SSH Connection Protocol, section 6.5. Starting a Shell or a Command</a>
 * @see ChannelSftpImpl
 */
public class ChannelSubsystemImpl
        extends ChannelSessionImpl
        implements ChannelSubsystem {

    private boolean waitForReply = true;

    @NonNull
    private String subsystem = "";

    public ChannelSubsystemImpl(@NonNull final SessionImpl session) {
        super(session);
    }

    @Override
    public void setSubsystem(@NonNull final String subsystem) {
        this.subsystem = subsystem;
    }

    @Override
    public void setWaitForReply(final boolean waitForReply) {
        this.waitForReply = waitForReply;
    }

    @Override
    protected void onAfterConnect(@NonNull final SessionImpl session)
            throws GeneralSecurityException, IOException, SshChannelException {

        sendSessionRequests();

        // byte      SSH_MSG_CHANNEL_REQUEST
        // uint32    recipient channel
        // string    "subsystem"
        // boolean   want reply
        // string    subsystem name
        sendRequest((recipient, wantReply) -> new Packet(SshConstants.SSH_MSG_CHANNEL_REQUEST)
                            .putInt(recipient)
                            .putString(ChannelSubsystem.NAME)
                            .putBoolean(wantReply)
                            .putString(subsystem),
                    waitForReply);

        if (ioStreams.hasInputStream()) {
            startThread();
        }
    }
}
