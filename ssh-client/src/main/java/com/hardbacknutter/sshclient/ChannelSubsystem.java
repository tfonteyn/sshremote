package com.hardbacknutter.sshclient;

import androidx.annotation.NonNull;

@SuppressWarnings("unused")
public interface ChannelSubsystem {

    String NAME = "subsystem";

    /**
     * Sets the name of the remote subsystem name.
     *
     * @param subsystem the name of the subsystem. It should consist of only
     *                  printable ASCII characters and be a subsystem name recognized
     *                  by the remote server process.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4250#section-4.6.1">
     * RFC 4250 SSH Protocol Assigned Numbers, section 4.6.1. Conventions for Names</a>
     */
    void setSubsystem(@NonNull String subsystem);

    /**
     * Indicates whether we want a confirmation/error reply to requests on this channel.
     * This will entirely depend on what subsystem is being addressed.
     * <p>
     * The default is {@code true}.
     */
    void setWaitForReply(boolean waitForReply);
}
