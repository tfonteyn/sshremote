package com.hardbacknutter.sshclient;

import java.io.IOException;
import java.security.GeneralSecurityException;

import com.hardbacknutter.sshclient.channels.SshChannelException;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

@SuppressWarnings("unused")
public interface ChannelSession
        extends Channel {

    /** Channel type/name. */
    String NAME = "session";

    /**
     * Enable SSH-Agent forwarding over this channel.
     *
     * @param enable flag
     */
    void setAgentForwarding(boolean enable);

    /**
     * Enable X11 forwarding.
     *
     * @param screenNumber to use; a negative value disables forwarding
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.3">
     *         RFC 4254 SSH Connection Protocol, section 6.3. Requesting X11 Forwarding</a>
     */
    void setXForwarding(int screenNumber);

    /**
     * Set an environment variable.
     * <p>
     * If {@code name} and {@code value} are needed to be passed
     * to the remote in your favorite encoding, use {@link #setEnv(byte[], byte[])}.
     *
     * @param name  A name for the environment variable.
     * @param value A value for the environment variable.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.4">
     *         RFC 4254 SSH Connection Protocol, section 6.4. Environment Variable Passing</a>
     */
    void setEnv(@NonNull String name,
                @NonNull String value);

    /**
     * Set an environment variable.
     *
     * @param name  A name for the environment variable.
     * @param value A value for the environment variable.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.4">
     *         RFC 4254 SSH Connection Protocol, section 6.4. Environment Variable Passing</a>
     */
    void setEnv(byte @NonNull [] name,
                byte @NonNull [] value);

    /**
     * Send the given signal to the process at the remote side.
     *
     * @param signal the signal name, without the "SIG" prefix.
     *
     * @throws SshChannelException      for channel specific errors
     * @throws GeneralSecurityException for generic security errors
     * @throws IOException              for generic IO errors
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.9">
     *         RFC 4254 SSH Connection Protocol, Section 6.9. Signals</a>
     */
    void sendSignal(@NonNull String signal)
            throws GeneralSecurityException, IOException, SshChannelException;

    /**
     * Can the client do flow control.
     *
     * @return flag
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.8">
     *         RFC 4254 SSH Connection Protocol, section 6.8. Local Flow Control</a>
     */
    boolean isClientCanDoFlowControl();

    /**
     * Retrieve the full {@link ExitStatus} record.
     *
     * @return status
     */
    @Nullable
    ExitStatus getExitStatus();

    /**
     * Determining the correct outcome:
     * <ol>
     *     <li>Check {@link #getSignalName()}.</li>
     *     <li>If the signal was NOT {@code null} you can also check {@link #isCoreDumped()}</li>
     *     <li>If the signal was {@code null}, check {@link #getStatus()}</li>
     *     <li>Either way, optionally check {@link #getMessage()}</li>
     * </ol>
     */
    interface ExitStatus {

        /**
         * Return code from {@link #getStatus()} if there was no error.
         */
        int NO_EXIT_STATUS = -1;

        /**
         * The exit status is only available for certain types of channels,
         * and only after the channel was closed (more exactly, just before
         * the channel is closed).
         * <p>
         * Contains the exit-status returned by the remote command,
         * or -1, if the command not yet terminated (or this channel type has no command).
         *
         * @return status
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.10">
         *         RFC 4254 SSH Connection Protocol, section 6.10. Returning Exit Status</a>
         */
        int getStatus();

        /**
         * Optional exit status message (determined by remote host).
         *
         * @return status
         */
        @Nullable
        String getMessage();

        /**
         * Exit signal if the remote host process threw a signal.
         * <p>
         * The 'signal name' is one of the following (these are from POSIX).
         * <pre>
         *       ABRT, ALRM, FPE, HUP, ILL, INT, KILL, PIPE, QUIT, SEGV, TERM, USR1, USR2
         *  </pre>
         * Additional 'signal name' values MAY be sent in the format "sig-name@xyz"
         *
         * @return name
         */
        @Nullable
        String getSignalName();

        /**
         * Did the process core-dump?
         * <p>
         * Only valid when/if the remote host process threw a signal;
         * i.e. when {@link #getSignalName()} is not {@code null}
         *
         * @return flag
         */
        boolean isCoreDumped();
    }
}
