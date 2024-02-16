package com.hardbacknutter.sshremote;

import android.content.Context;
import android.os.Bundle;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModel;

import java.util.List;

import com.hardbacknutter.sshremote.db.Command;
import com.hardbacknutter.sshremote.db.Config;
import com.hardbacknutter.sshremote.db.DB;
import com.hardbacknutter.sshremote.db.Host;

@SuppressWarnings("WeakerAccess")
public class EditButtonViewModel
        extends ViewModel {

    static final String ARGS_BUTTON_POSITION = "pos";

    private final MutableLiveData<Config> configLoaded = new MutableLiveData<>();

    private DB db;

    private int currentButton = -1;

    private Config config;
    private List<Host> hostList;
    private List<Command> commandList;

    void init(@NonNull final Context context,
              @Nullable final Bundle args) {

        if (db == null) {
            db = DB.getInstance(context);
        }

        // Always refresh the lists
        db.getExecutor().execute(() -> {
            hostList = db.getHostDao().getAll();
            commandList = db.getCommandDao().getAll();
        });

        // this vm is owned by the activity, so we need to keep track and replace data as needed
        final int position = args == null ? 0 : args.getInt(ARGS_BUTTON_POSITION, 0);
        if (currentButton != position) {
            currentButton = position;
            db.getExecutor().execute(() -> {
                //noinspection DataFlowIssue
                config = db.getConfigDao().findByPosition(position);
                if (config == null) {
                    config = new Config(position);
                }
                configLoaded.postValue(config);
            });
        }
    }

    @NonNull
    LiveData<Config> onConfigLoaded() {
        return configLoaded;
    }

    void setLabel(@NonNull final String label) {
        config.label = label;
    }

    int getHost() {
        return config.hostId;
    }

    void setHost(final int id) {
        config.hostId = id;
    }

    int getCommand() {
        return config.commandId;
    }

    void setCommand(final int id) {
        config.commandId = id;
    }

    @NonNull
    List<Host> getHostList() {
        return hostList;
    }

    @NonNull
    List<Command> getCommandList() {
        return commandList;
    }

    boolean save() {
        // can only save if both set
        if (config.commandId != 0 && config.hostId != 0) {
            db.getExecutor().execute(() -> {
                if (config.id == 0) {
                    db.getConfigDao().insert(config);
                } else {
                    db.getConfigDao().update(config);
                }
            });
            return true;
        } else {
            return false;
        }
    }

    void delete() {
        if (config.id != 0) {
            db.getExecutor().execute(() -> db.getConfigDao().delete(config));
        }
    }
}
