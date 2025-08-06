package com.hardbacknutter.sshclient;

import java.io.IOException;
import java.security.GeneralSecurityException;

import com.hardbacknutter.sshclient.channels.SshChannelException;

import org.jspecify.annotations.NonNull;

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

    /** Channel type/name. */
    String NAME = "shell";

    /**
     * Allocate a Pseudo-Terminal using all default settings.
     * This method is not effective after the channel is connected.
     *
     * @param enable flag
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.2">
     *         RFC 4254 SSH Connection Protocol, section 6.2. Requesting a Pseudo-Terminal</a>.
     */
    void setPty(boolean enable);

    /**
     * Set the terminal modes.
     * This method is not effective after Channel#connect().
     *
     * @param modes to set
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-8">
     *         RFC 4254 SSH Connection Protocol, section 8. Encoding of Terminal Modes</a>
     */
    void setPtyModes(byte @NonNull [] modes);

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
     * @throws SshChannelException      for channel specific errors
     * @throws GeneralSecurityException for generic security errors
     * @throws IOException              for generic IO errors
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.7">
     *         RFC 4254 SSH Connection Protocol, section 6.7. Window Dimension Change Message</a>
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
