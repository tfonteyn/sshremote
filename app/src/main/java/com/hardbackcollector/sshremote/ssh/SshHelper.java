package com.hardbackcollector.sshremote.ssh;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Log;

import androidx.annotation.IntRange;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.hardbackcollector.sshclient.Channel;
import com.hardbackcollector.sshclient.ChannelExec;
import com.hardbackcollector.sshclient.Logger;
import com.hardbackcollector.sshclient.Session;
import com.hardbackcollector.sshclient.SshClient;
import com.hardbackcollector.sshclient.channels.SshChannelException;
import com.hardbackcollector.sshclient.kex.KexProposal;
import com.hardbackcollector.sshclient.userauth.UserInfo;
import com.hardbackcollector.sshclient.utils.SshException;
import com.hardbackcollector.sshremote.db.Command;
import com.hardbackcollector.sshremote.db.Host;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.function.Supplier;
import java.util.stream.Collectors;

public class SshHelper {

    public static final String PK_SSH_LOG_LEVEL = "global.ssh.log.level";
    public static final String PK_STRICT_HOST_KEY_CHECKING = "global.ssh.strictHostKeyChecking";

    public static final String KNOWN_HOSTS = "known_hosts";
    private static final String CHANNEL_EXEC = "exec";
    @NonNull
    private final Host mHost;

    private final SshClient mSshClient;

    public SshHelper(@NonNull final SharedPreferences global,
                     @NonNull final Host host) {
        mHost = host;

        final int logLevel = global.getInt(PK_SSH_LOG_LEVEL, Logger.ERROR);

        mSshClient = new SshClient(new JLogger(logLevel));

        mSshClient.setConfig(KexProposal.PROPOSAL_COMP_CTOS,
                             KexProposal.COMPRESSION_ZLIB_OPENSSH_COM);
        mSshClient.setConfig(KexProposal.PROPOSAL_COMP_STOC,
                             KexProposal.COMPRESSION_ZLIB_OPENSSH_COM);
    }

    /**
     * @param context Current context
     * @return a new Session
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
        mSshClient.setKnownHosts(file.getAbsolutePath());

        // trim because paranoia
        final Session session = mSshClient.getSession(mHost.userName.trim(),
                mHost.hostnameOrIp.trim(),
                mHost.port);
        if (userInfo != null) {
            session.setUserInfo(userInfo);
        }
        session.setPassword(mHost.userPassword.trim());
        session.setConfig(mHost.getOptions());
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

    @NonNull
    public String read(@NonNull final Channel channel)
            throws IOException {
        try (final InputStream is = channel.getInputStream();
             final InputStreamReader isr = new InputStreamReader(is, StandardCharsets.UTF_8);
             final BufferedReader reader = new BufferedReader(isr)) {

            return reader.lines().collect(Collectors.joining("\n"));
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
            implements com.hardbackcollector.sshclient.Logger {

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
                        @NonNull final Supplier<String> message) {
            if (level >= this.level) {
                Log.d("SSH" + level, message.get());
            }
        }
    }
}
