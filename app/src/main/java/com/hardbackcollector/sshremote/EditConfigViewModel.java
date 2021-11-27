package com.hardbackcollector.sshremote;

import android.content.Context;
import android.os.Bundle;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModel;

import com.hardbackcollector.sshremote.db.Command;
import com.hardbackcollector.sshremote.db.Config;
import com.hardbackcollector.sshremote.db.DB;
import com.hardbackcollector.sshremote.db.Host;

import java.util.List;

@SuppressWarnings("WeakerAccess")
public class EditConfigViewModel
        extends ViewModel {

    static final String ARGS_BUTTON_POSITION = "pos";

    private final MutableLiveData<Config> mConfigLoaded = new MutableLiveData<>();

    private DB mDb;

    private int currentButton = -1;

    private Config mConfig;
    private List<Host> mHostList;
    private List<Command> mCommandList;

    void init(@NonNull final Context context,
              @Nullable final Bundle args) {

        if (mDb == null) {
            mDb = DB.getInstance(context);
        }

        // Always refresh the lists
        mDb.getExecutor().execute(() -> {
            mHostList = mDb.getHostDao().getAll();
            mCommandList = mDb.getCommandDao().getAll();
        });

        // this vm is owned by the activity, so we need to keep track and replace data as needed
        final int position = args == null ? 0 : args.getInt(ARGS_BUTTON_POSITION, 0);
        if (currentButton != position) {
            currentButton = position;
            mDb.getExecutor().execute(() -> {
                //noinspection ConstantConditions
                mConfig = mDb.getConfigDao().findByPosition(position);
                if (mConfig == null) {
                    mConfig = new Config(position);
                }
                mConfigLoaded.postValue(mConfig);
            });
        }
    }

    @NonNull
    LiveData<Config> onConfigLoaded() {
        return mConfigLoaded;
    }

    void setLabel(@NonNull final String label) {
        mConfig.label = label;
    }

    int getHost() {
        return mConfig.hostId;
    }

    void setHost(final int id) {
        mConfig.hostId = id;
    }

    int getCommand() {
        return mConfig.commandId;
    }

    void setCommand(final int id) {
        mConfig.commandId = id;
    }

    @NonNull
    List<Host> getHostList() {
        return mHostList;
    }

    @NonNull
    List<Command> getCommandList() {
        return mCommandList;
    }

    boolean save() {
        // can only save if both set
        if (mConfig.commandId != 0 && mConfig.hostId != 0) {
            mDb.getExecutor().execute(() -> {
                if (mConfig.id == 0) {
                    mDb.getConfigDao().insert(mConfig);
                } else {
                    mDb.getConfigDao().update(mConfig);
                }
            });
            return true;
        } else {
            return false;
        }
    }

    void delete() {
        if (mConfig.id != 0) {
            mDb.getExecutor().execute(() -> mDb.getConfigDao().delete(mConfig));
        }
    }
}
