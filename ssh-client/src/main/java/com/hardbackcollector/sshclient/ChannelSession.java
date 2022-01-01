package com.hardbackcollector.sshclient;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.channels.SshChannelException;

import java.io.IOException;
import java.security.GeneralSecurityException;

@SuppressWarnings("unused")
public interface ChannelSession
        extends Channel {

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
     * RFC 4254 SSH Connection Protocol, section 6.3. Requesting X11 Forwarding</a>
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
     * RFC 4254 SSH Connection Protocol, section 6.4. Environment Variable Passing</a>
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
     * RFC 4254 SSH Connection Protocol, section 6.4. Environment Variable Passing</a>
     */
    void setEnv(@NonNull byte[] name,
                @NonNull byte[] value);

    /**
     * Send the given signal to the process at the remote side.
     *
     * @param signal the signal name, without the "SIG" prefix.
     *
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.9">
     * RFC 4254 SSH Connection Protocol, Section 6.9. Signals</a>
     */
    void sendSignal(@NonNull String signal)
            throws GeneralSecurityException, IOException, SshChannelException;

    /**
     * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.8">
     * RFC 4254 SSH Connection Protocol, section 6.8. Local Flow Control</a>
     */
    boolean isClientCanDoFlowControl();

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

        int NO_EXIT_STATUS = -1;

        /**
         * The exit status is only available for certain types of channels,
         * and only after the channel was closed (more exactly, just before
         * the channel is closed).
         * <p>
         * Contains the exit-status returned by the remote command,
         * or -1, if the command not yet terminated (or this channel type has no command).
         *
         * @see <a href="https://datatracker.ietf.org/doc/html/rfc4254#section-6.10">
         * RFC 4254 SSH Connection Protocol, section 6.10. Returning Exit Status</a>
         */
        int getStatus();

        /**
         * Optional exit status message (determined by remote host).
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
         */
        @Nullable
        String getSignalName();

        /**
         * Did the process core-dump?
         * <p>
         * Only valid when/if the remote host process threw a signal;
         * i.e. when {@link #getSignalName()} is not {@code null}
         */
        boolean isCoreDumped();
    }
}
