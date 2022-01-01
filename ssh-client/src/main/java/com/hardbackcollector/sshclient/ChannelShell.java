package com.hardbackcollector.sshclient;

import androidx.annotation.NonNull;

import com.hardbackcollector.sshclient.channels.SshChannelException;

import java.io.IOException;
import java.security.GeneralSecurityException;

/**
 * A channel connected to a remote shell.
 * <pre>
 *     ChannelShell channel = (ChannelShell)
 *          session.{@link Session#openChannel openChannel}(NAME);
 *  </pre>
 */
@SuppressWarnings("unused")
public interface ChannelShell
        extends ChannelSession {

    String NAME = "shell";

    void setPty(final boolean enable);

    /**
     * Set the terminal modes.
     * This method is not effective after Channel#connect().
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-8">
     * RFC 4254 SSH Connection Protocol, section 8. Encoding of Terminal Modes</a>
     */
    void setPtyModes(@NonNull byte[] modes);

    /**
     * Set the terminal type.
     * This method is not effective after Channel#connect().
     *
     * @param type terminal type (e.g. "vt100")
     */
    void setPtyType(@NonNull String type);

    /**
     * Set or change the window dimensions interactively.
     *
     * @param columns        terminal width
     * @param rows           terminal height
     * @param widthInPixels  terminal width
     * @param heightInPixels terminal height
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.7">
     * RFC 4254 SSH Connection Protocol, section 6.7. Window Dimension Change Message</a>
     */
    void setPtySize(int columns,
                    int rows,
                    int widthInPixels,
                    int heightInPixels)
            throws SshChannelException, GeneralSecurityException, IOException;

    /**
     * Whether to wait for a reply to the open request.
     * <p>
     * The default is {@code true}.
     *
     * @param waitForReply flag
     */
    void setWaitForReply(boolean waitForReply);
}
