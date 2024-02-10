package com.hardbacknutter.sshremote;

import android.content.Context;
import android.os.Bundle;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModel;
import androidx.lifecycle.ViewModelProvider;
import androidx.lifecycle.ViewModelStoreOwner;

import com.hardbacknutter.sshremote.db.Command;
import com.hardbacknutter.sshremote.db.DB;

@SuppressWarnings("WeakerAccess")
public class EditCommandViewModel
        extends ViewModel {

    static final String ARGS_ID = "id";

    private final MutableLiveData<Command> commandLoaded = new MutableLiveData<>();

    private Command command;
    private DB db;

    void init(@NonNull final Context context,
              @Nullable final Bundle args) {
        if (db == null) {
            db = DB.getInstance(context);

            final int id = args == null ? 0 : args.getInt(ARGS_ID, 0);
            if (id > 0) {
                db.getExecutor().execute(() -> {
                    command = db.getCommandDao().findById(id);
                    commandLoaded.postValue(command);
                });
            } else {
                command = new Command();
                commandLoaded.setValue(command);
            }
        }
    }

    @NonNull
    LiveData<Command> onConfigLoaded() {
        return commandLoaded;
    }

    void setSudo(final boolean isSudo) {
        command.isSudo = isSudo;
    }

    void setSudoPassword(@NonNull final String password) {
        command.sudoPassword = password;
    }

    void setCommand(@NonNull final String cmd) {
        command.cmd = cmd;
    }

    void setLabel(@NonNull final String label) {
        command.label = label;
    }

    void save(@NonNull final ViewModelStoreOwner owner) {
        final EditConfigViewModel cvm = new ViewModelProvider(owner)
                .get(EditConfigViewModel.class);
        db.getExecutor().execute(() -> {
            if (command.id == 0) {
                cvm.setCommand((int) db.getCommandDao().insert(command));
            } else {
                db.getCommandDao().update(command);
            }
        });
    }

    void delete(@NonNull final ViewModelStoreOwner owner) {
        final EditConfigViewModel cvm = new ViewModelProvider(owner)
                .get(EditConfigViewModel.class);
        db.getExecutor().execute(() -> {
            db.getCommandDao().delete(command);
            cvm.setCommand(0);
        });
    }
}
