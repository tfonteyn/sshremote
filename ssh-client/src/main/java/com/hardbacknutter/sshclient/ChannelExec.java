package com.hardbacknutter.sshclient;

import org.jspecify.annotations.NonNull;

@SuppressWarnings("unused")
public interface ChannelExec
        extends ChannelSession {

    /** Channel type/name. */
    String NAME = "exec";

    /**
     * sets the command to be executed.
     *
     * @param command the command to be executed.
     *                We will use the platform's default encoding
     *                to encode this string.
     */
    void setCommand(@NonNull String command);

    /**
     * Whether to wait for a reply to the open request.
     * <p>
     * The default is {@code false}.
     *
     * @param waitForReply flag
     */
    void setWaitForReply(boolean waitForReply);
}
