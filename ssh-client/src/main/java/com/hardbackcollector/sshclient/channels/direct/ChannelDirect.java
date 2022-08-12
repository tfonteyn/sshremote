package com.hardbackcollector.sshclient.channels.direct;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.Logger;
import com.hardbackcollector.sshclient.channels.BaseChannel;
import com.hardbackcollector.sshclient.channels.SshChannelException;
import com.hardbackcollector.sshclient.transport.SessionImpl;

import java.io.IOException;
import java.security.GeneralSecurityException;

public abstract class ChannelDirect
        extends BaseChannel {

    ChannelDirect(@NonNull final String type,
                  @NonNull final SessionImpl session) {
        super(type, session);
    }

    @Override
    public void connect(final int connectTimeout)
            throws SshChannelException, IOException, GeneralSecurityException {

        if (ioStreams.hasInputStream()) {
            if (!session.isConnected()) {
                disconnect();
                throw new SshChannelException(ERROR_SESSION_NOT_CONNECTED);
            }

            setConnectTimeout(connectTimeout);
            startThread();

        } else {
            super.connect(connectTimeout);
        }
    }

    /**
     * The channel transfer loop.
     */
    @Override
    protected void run() {
        try {
            sendChannelOpen();

        } catch (final Exception e) {
            if (session.getLogger().isEnabled(Logger.ERROR)) {
                session.getLogger().log(Logger.ERROR, e, () -> "ChannelDirect:" + getType());
            }

            // Whenever an exception is thrown by sendChannelOpen(),
            // 'connected' is false.
            if (!connected) {
                connected = true;
            }
            disconnect();
            return;
        }

        runDataTransferLoop();
    }
}
