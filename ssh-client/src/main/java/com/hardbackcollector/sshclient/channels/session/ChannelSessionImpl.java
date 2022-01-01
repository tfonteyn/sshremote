package com.hardbackcollector.sshclient.channels.session;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.ChannelSession;
import com.hardbackcollector.sshclient.channels.BaseChannel;
import com.hardbackcollector.sshclient.channels.SshChannelException;
import com.hardbackcollector.sshclient.channels.forward.ChannelX11;
import com.hardbackcollector.sshclient.transport.Packet;
import com.hardbackcollector.sshclient.transport.SessionImpl;
import com.hardbackcollector.sshclient.utils.SshConstants;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;

/**
 * Base class for all Interactive Sessions channels.
 * <p>
 * A session is a remote execution of a program.  The program may be a
 * shell, an application, a system command, or some built-in subsystem.
 * It may or may not have a tty, and may or may not involve X11
 * forwarding.  Multiple sessions can be active simultaneously.
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6">
 * RFC 4254 SSH Connection Protocol, section 6. Interactive Sessions</a>
 */
public class ChannelSessionImpl
        extends BaseChannel
        implements ChannelSession {

    private boolean agent_forwarding;
    /** Screen number for X11; -1 for no forwarding. */
    private int x11_forwarding = -1;

    @Nullable
    private Map<byte[], byte[]> env;

    private boolean pty;

    /** TERM environment variable value (e.g., vt100). */
    @NonNull
    private String ptyTerm = "vt100";
    @NonNull
    private byte[] ptyModes = "".getBytes(StandardCharsets.UTF_8);

    private int ptyColumns = 80;
    private int ptyRows = 24;
    private int ptyWidthInPixels = 640;
    private int ptyHeightInPixels = 480;

    /** Xon/Xoff support. */
    private boolean clientCanDoFlowControl;

    @Nullable
    private ChannelExitStatusImpl exitStatus;

    public ChannelSessionImpl(@NonNull final SessionImpl session) {
        super(NAME, session);
    }

    @Override
    public void setAgentForwarding(final boolean enable) {
        agent_forwarding = enable;
    }

    @Override
    public void setXForwarding(final int screenNumber) {
        x11_forwarding = screenNumber;
    }

    @Override
    public void setEnv(@NonNull final String name,
                       @NonNull final String value) {
        setEnv(name.getBytes(StandardCharsets.UTF_8),
               value.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public void setEnv(@NonNull final byte[] name,
                       @NonNull final byte[] value) {
        synchronized (this) {
            if (env == null) {
                env = new HashMap<>();
            }
            env.put(name, value);
        }
    }

    /**
     * Allocate a Pseudo-Terminal using all default settings.
     * This method is not effective after the channel is connected.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.2">
     * RFC 4254 SSH Connection Protocol, section 6.2. Requesting a Pseudo-Terminal</a>.
     */
    public void setPty(final boolean enable) {
        this.pty = enable;
    }

    /**
     * Set the terminal modes.
     * This method is not effective after the channel is connected.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-8">
     * RFC 4254 SSH Connection Protocol, section 8. Encoding of Terminal Modes</a>
     */
    public void setPtyModes(@NonNull final byte[] modes) {
        this.ptyModes = modes;
    }

    /**
     * Set the terminal type.
     * This method is not effective after the channel is connected.
     *
     * @param type terminal type (e.g. "vt100")
     */
    public void setPtyType(@NonNull final String type) {
        this.ptyTerm = type;
    }

    /**
     * Set or change the window dimensions interactively.
     *
     * @param columns        terminal width
     * @param rows           terminal height
     * @param widthInPixels  terminal width
     * @param heightInPixels terminal height
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.7">
     * RFC SSH 4254 Connection Protocol, section 6.7. Window Dimension Change Message</a>
     */
    public void setPtySize(final int columns,
                           final int rows,
                           final int widthInPixels,
                           final int heightInPixels)
            throws SshChannelException, GeneralSecurityException, IOException {

        this.ptyColumns = columns;
        this.ptyRows = rows;
        this.ptyWidthInPixels = widthInPixels;
        this.ptyHeightInPixels = heightInPixels;

        // if already connected, send a change request
        if (isConnected()) {
            sendWindowChangeRequest();
        }
    }

    @Override
    public void sendSignal(@NonNull final String signal)
            throws GeneralSecurityException, IOException, SshChannelException {

        // byte      SSH_MSG_CHANNEL_REQUEST
        // uint32    recipient channel
        // string    "signal"
        // boolean   FALSE
        // string    signal name (without the "SIG" prefix)
        sendRequest((recipient, x) -> new Packet(SshConstants.SSH_MSG_CHANNEL_REQUEST)
                            .putInt(recipient)
                            .putString("signal")
                            .putBoolean(false)
                            .putString(signal),
                    false);
    }

    @Override
    public boolean isClientCanDoFlowControl() {
        return clientCanDoFlowControl;
    }

    @Nullable
    @Override
    public ExitStatus getExitStatus() {
        return exitStatus;
    }


    /**
     * creates and sends all requests enabled by
     * {@link #setAgentForwarding},
     * {@link #setXForwarding},
     * {@link #setPty}
     * and
     * {@link #setEnv}.
     */
    void sendSessionRequests()
            throws GeneralSecurityException, IOException, SshChannelException {

        if (agent_forwarding) {
            sendAgentForwardingRequest();
        }

        if (x11_forwarding >= 0) {
            sendX11ForwardingRequest();
        }

        if (pty) {
            sendPtyRequest();
        }

        if (env != null) {
            for (final Map.Entry<byte[], byte[]> entry : env.entrySet()) {
                sendEnvRequest(toByteArray(entry.getKey()), toByteArray(entry.getValue()));
            }
        }
    }

    private void sendAgentForwardingRequest()
            throws GeneralSecurityException, IOException, SshChannelException {
        // byte     SSH_MSG_CHANNEL_REQUEST
        // uint32   recipient channel
        // string   "auth-agent-req@openssh.com"
        // boolean  want reply
        sendRequest((recipient, x) -> new Packet(SshConstants.SSH_MSG_CHANNEL_REQUEST)
                            .putInt(recipient)
                            .putString("auth-agent-req@openssh.com")
                            .putBoolean(false),
                    false);
    }

    private void sendX11ForwardingRequest()
            throws GeneralSecurityException, IOException, SshChannelException {
        // byte      SSH_MSG_CHANNEL_REQUEST
        // uint32    recipient channel
        // string    "x11-req"
        // boolean   want reply
        // boolean   single connection
        // string    x11 authentication protocol: "MIT-MAGIC-COOKIE-1"
        // string    x11 authentication cookie (hex-encoded 32 byte)
        // uint32    x11 screen number
        sendRequest((recipient, x) -> new Packet(SshConstants.SSH_MSG_CHANNEL_REQUEST)
                            .putInt(recipient)
                            .putString("x11-req")
                            .putBoolean(false)
                            .putBoolean(false)
                            .putString("MIT-MAGIC-COOKIE-1")
                            .putString(ChannelX11.getHexEncodedAuthCookie(getSession()))
                            .putInt(x11_forwarding),
                    false);
    }

    /**
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.4">
     * RFC 4254 SSH Connection Protocol, section 6.4. Environment Variable Passing</a>
     */
    private void sendEnvRequest(final byte[] name,
                                final byte[] value)
            throws GeneralSecurityException, IOException, SshChannelException {
        // byte      SSH_MSG_CHANNEL_REQUEST
        // uint32    recipient channel
        // string    "env"
        // boolean   want reply
        // string    variable name
        // string    variable value
        sendRequest((recipient, x) -> new Packet(SshConstants.SSH_MSG_CHANNEL_REQUEST)
                .putInt(recipient)
                .putString("env")
                .putBoolean(false)
                .putString(name)
                .putString(value), false);
    }

    /**
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.2">
     * RFC 4254 SSH Connection Protocol, section 6.2. Requesting a Pseudo-Terminal</a>
     */
    private void sendPtyRequest()
            throws GeneralSecurityException, IOException, SshChannelException {

        // byte      SSH_MSG_CHANNEL_REQUEST
        // uint32    recipient channel
        // string    "pty-req"
        // boolean   want_reply
        // string    TERM environment variable value (e.g., vt100)
        // uint32    terminal width, characters (e.g., 80)
        // uint32    terminal height, rows (e.g., 24)
        // uint32    terminal width, pixels (e.g., 640)
        // uint32    terminal height, pixels (e.g., 480)
        // string    encoded terminal modes
        sendRequest((recipient, x) -> new Packet(SshConstants.SSH_MSG_CHANNEL_REQUEST)
                            .putInt(recipient)
                            .putString("pty-req")
                            .putBoolean(false)
                            .putString(ptyTerm)
                            .putInt(ptyColumns)
                            .putInt(ptyRows)
                            .putInt(ptyWidthInPixels)
                            .putInt(ptyHeightInPixels)
                            .putString(ptyModes),
                    false);
    }

    /**
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.7">
     * RFC 4254 SSH Connection Protocol, section 6.7. Window Dimension Change Message</a>
     */
    private void sendWindowChangeRequest()
            throws GeneralSecurityException, IOException, SshChannelException {

        //byte      SSH_MSG_CHANNEL_REQUEST
        //uint32    recipient_channel
        //string    "window-change"
        //boolean   FALSE
        //uint32    terminal width, columns
        //uint32    terminal height, rows
        //uint32    terminal width, pixels
        //uint32    terminal height, pixels
        sendRequest((recipient, x) -> new Packet(SshConstants.SSH_MSG_CHANNEL_REQUEST)
                            .putInt(recipient)
                            .putString("window-change")
                            .putBoolean(false)
                            .putInt(ptyColumns)
                            .putInt(ptyRows)
                            .putInt(ptyWidthInPixels)
                            .putInt(ptyHeightInPixels),
                    false);
    }


    /**
     * The channel transfer loop.
     */
    @Override
    public void run() {
        runDataTransferLoop();
    }

    /**
     * Handle an incoming command/packet meant for this channel.
     *
     * @param packet to handle
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.10">
     * RFC 4254 SSH Connection Protocol, section 6.10. Returning Exit Status</a>
     */
    @Override
    public void handle(@NonNull final Packet packet)
            throws IOException, GeneralSecurityException {
        if (packet.getCommand() == SshConstants.SSH_MSG_CHANNEL_REQUEST) {
            // Packet.PAYLOAD_START(5) + command(1) + recipient(4) == 10
            packet.setReadOffSet(10);
            final String requestType = packet.getJString();
            //noinspection SwitchStatementWithoutDefaultBranch
            switch (requestType) {
                case "exit-status": {
                    packet.getBoolean(); // want-reply: FALSE
                    exitStatus = new ChannelExitStatusImpl(packet.getInt());
                    return;
                }
                case "exit-signal": {
                    packet.getBoolean(); // want-reply: FALSE
                    exitStatus = new ChannelExitStatusImpl(packet.getJString(),
                                                           packet.getBoolean(),
                                                           packet.getJString());
                    packet.skipString(/* language_tag */);
                    return;
                }
                case "xon-xoff": {
                    // byte      SSH_MSG_CHANNEL_REQUEST
                    // uint32    recipient channel
                    // string    "xon-xoff"
                    // boolean   FALSE
                    // boolean   client can do
                    packet.getBoolean(); // want-reply: FALSE
                    clientCanDoFlowControl = packet.getBoolean();
                    return;
                }
            }
        }

        super.handle(packet);
    }

    @NonNull
    private byte[] toByteArray(@NonNull final Object o) {
        if (o instanceof String) {
            return ((String) o).getBytes(StandardCharsets.UTF_8);
        }
        return (byte[]) o;
    }
}
