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
package com.hardbackcollector.sshclient.channels.session;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.ChannelExec;
import com.hardbackcollector.sshclient.channels.SshChannelException;
import com.hardbackcollector.sshclient.transport.Packet;
import com.hardbackcollector.sshclient.transport.SessionImpl;
import com.hardbackcollector.sshclient.utils.SshConstants;

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
