package com.hardbacknutter.sshremote;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.preference.PreferenceManager;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Objects;

import com.hardbacknutter.sshclient.ChannelExec;
import com.hardbacknutter.sshclient.ChannelSession;
import com.hardbacknutter.sshclient.Session;
import com.hardbacknutter.sshclient.utils.SshException;
import com.hardbacknutter.sshremote.db.Command;
import com.hardbacknutter.sshremote.db.Config;
import com.hardbacknutter.sshremote.db.DB;
import com.hardbacknutter.sshremote.db.Host;
import com.hardbacknutter.sshremote.ssh.SshHelper;

public class UserButton {

    @NonNull
    private final Config config;
    @Nullable
    private final Host host;
    @Nullable
    private final Command command;
    @Nullable
    private ChannelSession.ExitStatus exitStatus;
    @Nullable
    private String output;

    UserButton(@NonNull final DB db,
               final int position) {

        config = Objects.requireNonNullElseGet(db.getConfigDao().findByPosition(position),
                                               () -> new Config(position));

        if (config.hostId != 0) {
            host = db.getHostDao().findById(config.hostId);
        } else {
            host = new Host();
        }

        if (config.commandId != 0) {
            command = db.getCommandDao().findById(config.commandId);
        } else {
            command = new Command();
        }
    }

    int getPosition() {
        return config.position;
    }

    void setPosition(final int position) {
        config.position = position;
    }

    public void update(@NonNull final DB db) {
        db.getConfigDao().update(config);
    }

    @NonNull
    String getLabel() {
        return config.label != null ? config.label : "";
    }

    boolean isPersisted() {
        return config.id != 0;
    }

    @Nullable
    String getOutput() {
        return output;
    }

    @Nullable
    ChannelSession.ExitStatus getExitStatus() {
        return exitStatus;
    }

    void exec(@NonNull final Context context)
            throws NotConfiguredException, IOException, GeneralSecurityException, SshException {

        if (host == null || command == null) {
            throw new NotConfiguredException();
        }

        host.ping();

        output = null;
        exitStatus = null;

        Session session = null;
        ChannelExec channel = null;

        final SharedPreferences global = PreferenceManager.getDefaultSharedPreferences(context);
        final boolean strict = global
                .getBoolean(SshHelper.PK_STRICT_HOST_KEY_CHECKING, true);

        // For now we don't let the user configure 'strict' on a per-host basis.
        // so we simply override with the global value
        host.strictHostKeyChecking = strict;

        final SshHelper ssh = new SshHelper(global, host);
        try {
            session = ssh.openSession(context, null);
            channel = ssh.openChannelExec(session, command);

            if (command.isSudo) {
                final String password = command.sudoPassword.isEmpty()
                                        ? host.userPassword
                                        : command.sudoPassword;
                ssh.writeln(channel, password);
            }
            output = ssh.read(channel);

        } finally {
            if (channel != null) {
                exitStatus = channel.getExitStatus();
            }
            ssh.safeClose(session, channel);
        }
    }
}
