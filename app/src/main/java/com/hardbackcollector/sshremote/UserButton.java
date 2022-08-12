package com.hardbackcollector.sshremote;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.preference.PreferenceManager;

import com.hardbackcollector.sshclient.ChannelExec;
import com.hardbackcollector.sshclient.ChannelSession;
import com.hardbackcollector.sshclient.Session;
import com.hardbackcollector.sshclient.utils.SshException;
import com.hardbackcollector.sshremote.db.Command;
import com.hardbackcollector.sshremote.db.Config;
import com.hardbackcollector.sshremote.db.DB;
import com.hardbackcollector.sshremote.db.Host;
import com.hardbackcollector.sshremote.ssh.SshHelper;

import java.io.IOException;
import java.security.GeneralSecurityException;

class UserButton {

    @NonNull
    private final Config mConfig;
    @Nullable
    private final Host mHost;
    @Nullable
    private final Command mCommand;
    @Nullable
    private ChannelSession.ExitStatus mExitStatus;
    @Nullable
    private String mOutput;

    UserButton(@NonNull final DB db,
               final int position) {

        final Config config = db.getConfigDao().findByPosition(position);
        if (config == null) {
            mConfig = new Config(position);
        } else {
            mConfig = config;
        }

        if (mConfig.hostId != 0) {
            mHost = db.getHostDao().findById(mConfig.hostId);
        } else {
            mHost = new Host();
        }

        if (mConfig.commandId != 0) {
            mCommand = db.getCommandDao().findById(mConfig.commandId);
        } else {
            mCommand = new Command();
        }
    }

    int getPosition() {
        return mConfig.position;
    }

    void setPosition(final int position) {
        mConfig.position = position;
    }

    public void update(@NonNull final DB db) {
        db.getConfigDao().update(mConfig);
    }

    @NonNull
    String getLabel() {
        return mConfig.label != null ? mConfig.label : "";
    }

    boolean isPersisted() {
        return mConfig.id != 0;
    }

    @Nullable
    String getOutput() {
        return mOutput;
    }

    @Nullable
    ChannelSession.ExitStatus getExitStatus() {
        return mExitStatus;
    }

    void exec(@NonNull final Context context)
            throws NotConfiguredException, IOException, GeneralSecurityException, SshException {

        if (mHost == null || mCommand == null) {
            throw new NotConfiguredException();
        }

        mHost.ping();

        mOutput = null;
        mExitStatus = null;

        Session session = null;
        ChannelExec channel = null;

        final SharedPreferences global = PreferenceManager.getDefaultSharedPreferences(context);
        final boolean strict = global
                .getBoolean(SshHelper.PK_STRICT_HOST_KEY_CHECKING, true);

        // For now we don't let the user configure 'strict' on a per-host basis.
        // so we simply override with the global value
        mHost.strictHostKeyChecking = strict;

        final SshHelper ssh = new SshHelper(global, mHost);
        try {
            session = ssh.openSession(context, null);
            channel = ssh.openChannelExec(session, mCommand);

            if (mCommand.isSudo) {
                final String password = mCommand.sudoPassword.isEmpty()
                        ? mHost.userPassword
                        : mCommand.sudoPassword;
                ssh.writeln(channel, password);
            }
            mOutput = ssh.read(channel);

        } finally {
            if (channel != null) {
                mExitStatus = channel.getExitStatus();
            }
            ssh.safeClose(session, channel);
        }
    }
}
