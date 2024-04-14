package com.hardbacknutter.sshremote.ssh;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import androidx.annotation.IntRange;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.stream.Collectors;

import com.hardbacknutter.sshclient.Channel;
import com.hardbacknutter.sshclient.ChannelExec;
import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.SshClient;
import com.hardbacknutter.sshclient.SshClientFactory;
import com.hardbacknutter.sshclient.channels.SshChannelException;
import com.hardbacknutter.sshclient.kex.KexProposal;
import com.hardbacknutter.sshclient.userauth.UserInfo;
import com.hardbacknutter.sshclient.utils.SshException;
import com.hardbacknutter.sshremote.db.Command;
import com.hardbacknutter.sshremote.db.Host;

public class SshHelper {

    public static final String PK_SSH_LOG_LEVEL = "global.ssh.log.level";
    public static final String PK_STRICT_HOST_KEY_CHECKING = "global.ssh.strictHostKeyChecking";

    public static final String KNOWN_HOSTS = "known_hosts";
    private static final String CHANNEL_EXEC = "exec";
    @NonNull
    private final Host host;

    private final SshClient sshClient;

    public SshHelper(@NonNull final SharedPreferences global,
                     @NonNull final Host host) {
        this.host = host;

        final int logLevel = global.getInt(PK_SSH_LOG_LEVEL, Logger.ERROR);

        sshClient = SshClientFactory.create(new JLogger(logLevel));

        sshClient.setConfig(KexProposal.PROPOSAL_COMP_CTOS,
                            KexProposal.COMPRESSION_ZLIB_OPENSSH_COM);
        sshClient.setConfig(KexProposal.PROPOSAL_COMP_STOC,
                            KexProposal.COMPRESSION_ZLIB_OPENSSH_COM);
    }

    /**
     * @param context Current context
     *
     * @return a new Session
     *
     * @throws IOException if the known-host repo could not be read
     */
    @NonNull
    public Session openSession(@NonNull final Context context,
                               @Nullable final UserInfo userInfo)
            throws SshException, IOException, GeneralSecurityException {

        // using our "known_hosts" as the HostKeyRepository
        final File file = new File(context.getFilesDir(), KNOWN_HOSTS);
        //noinspection ResultOfMethodCallIgnored
        file.createNewFile();
        sshClient.setKnownHosts(file.getAbsolutePath());

        // trim because paranoia
        final Session session = sshClient.getSession(host.userName.trim(),
                                                     host.hostnameOrIp.trim(),
                                                     host.port);
        if (userInfo != null) {
            session.setUserInfo(userInfo);
        }
        session.setPassword(host.userPassword.trim());
        session.setConfig(host.getOptions());
        session.connect();
        return session;
    }

    @NonNull
    public ChannelExec openChannelExec(@NonNull final Session session,
                                       @NonNull final Command command)
            throws GeneralSecurityException, IOException, SshChannelException {
        final ChannelExec channel = session.openChannel(CHANNEL_EXEC);
        channel.setCommand(command.getCommandLine());
        channel.connect();
        return channel;
    }

    /**
     * Read <strong>ALL</strong> of the data from the given channel.
     *
     * @param channel to read from
     *
     * @return a single String with all of the output
     *
     * @throws IOException on any error (including 'too much output')
     */
    @NonNull
    public String read(@NonNull final Channel channel)
            throws IOException {
        try (final InputStream is = channel.getInputStream();
             final InputStreamReader isr = new InputStreamReader(is, StandardCharsets.UTF_8);
             final BufferedReader reader = new BufferedReader(isr)) {

            return reader.lines().collect(Collectors.joining("\n"));
        } catch (@NonNull final OutOfMemoryError oom) {
            // this is due to the user running some command which returns a LOT of output.
            // The code above is simple/stupid and cannot cope with this.
            // Hope for the best... there is no guarantee this call will force a gc though
            System.gc();
            throw new IOException("Too much output");
        }
    }

    public void writeln(@NonNull final Channel channel,
                        @NonNull final String text)
            throws IOException {
        try (final OutputStream out = channel.getOutputStream()) {
            out.write((text + "\n").getBytes(StandardCharsets.UTF_8));
            out.flush();
        }
    }

    public void safeClose(@Nullable final Session session,
                          @Nullable final Channel channel) {
        if (channel != null) {
            channel.disconnect();
        }
        if (session != null) {
            session.disconnect();
        }
    }

    public static class JLogger
            implements com.hardbacknutter.sshclient.Logger {

        @IntRange(from = Logger.NONE, to = Logger.DEBUG)
        private final int level;

        JLogger(@IntRange(from = Logger.NONE, to = Logger.DEBUG) final int logLevel) {
            level = logLevel;
        }

        @Override
        public boolean isEnabled(final int level) {
            return level >= this.level;
        }

        @Override
        public void log(final int level,
                        @NonNull final String message) {
            Log.d("SSH" + level, message);
        }
    }
}
