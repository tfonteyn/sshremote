package com.hardbackcollector.sshremote;

import android.content.Context;
import android.os.Bundle;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModel;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStoreOwner;

import com.hardbackcollector.sshremote.db.Command;
import com.hardbackcollector.sshremote.db.DB;

@SuppressWarnings("WeakerAccess")
public class EditCommandViewModel
        extends ViewModel {

    static final String ARGS_ID = "id";

    private final MutableLiveData<Command> mCommandLoaded = new MutableLiveData<>();

    private Command mCommand;
    private DB mDb;

    void init(@NonNull final Context context,
              @Nullable final Bundle args) {
        if (mDb == null) {
            mDb = DB.getInstance(context);

            final int id = args == null ? 0 : args.getInt(ARGS_ID, 0);
            Log.d("command", "id=" + id);
            if (id > 0) {
                mDb.getExecutor().execute(() -> {
                    mCommand = mDb.getCommandDao().findById(id);
                    mCommandLoaded.postValue(mCommand);
                });
            } else {
                mCommand = new Command();
                mCommandLoaded.setValue(mCommand);
            }
        }
    }

    @NonNull
    LiveData<Command> onConfigLoaded() {
        return mCommandLoaded;
    }

    void setSudo(final boolean isSudo) {
        mCommand.isSudo = isSudo;
    }

    void setSudoPassword(@NonNull final String password) {
        mCommand.sudoPassword = password;
    }

    void setCommand(@NonNull final String cmd) {
        mCommand.cmd = cmd;
    }

    void setLabel(@NonNull final String label) {
        mCommand.label = label;
    }

    void save(@NonNull final ViewModelStoreOwner owner) {
        final EditConfigViewModel cvm = new ViewModelProvider(owner)
                .get(EditConfigViewModel.class);
        mDb.getExecutor().execute(() -> {
            if (mCommand.id == 0) {
                cvm.setCommand((int) mDb.getCommandDao().insert(mCommand));
            } else {
                mDb.getCommandDao().update(mCommand);
            }
        });
    }

    void delete(@NonNull final ViewModelStoreOwner owner) {
        final EditConfigViewModel cvm = new ViewModelProvider(owner)
                .get(EditConfigViewModel.class);
        mDb.getExecutor().execute(() -> {
            mDb.getCommandDao().delete(mCommand);
            cvm.setCommand(0);
        });
    }
}
