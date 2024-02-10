package com.hardbacknutter.sshremote;

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

import com.hardbacknutter.sshremote.db.DB;
import com.hardbacknutter.sshremote.db.Host;

@SuppressWarnings("WeakerAccess")
public class EditHostViewModel
        extends ViewModel {

    static final String ARGS_ID = "id";

    private final MutableLiveData<Host> hostLoaded = new MutableLiveData<>();

    private Host host;
    private DB db;

    void init(@NonNull final Context context,
              @Nullable final Bundle args) {
        if (db == null) {
            db = DB.getInstance(context);

            final int id = args == null ? 0 : args.getInt(ARGS_ID, 0);
            Log.d("host", "id=" + id);
            if (id > 0) {
                db.getExecutor().execute(() -> {
                    host = db.getHostDao().findById(id);
                    hostLoaded.postValue(host);
                });
            } else {
                host = new Host();
                hostLoaded.setValue(host);
            }
        }
    }

    @NonNull
    LiveData<Host> onConfigLoaded() {
        return hostLoaded;
    }

    void setLabel(@NonNull final String label) {
        host.label = label;
    }

    void setHost(@NonNull final String hostname) {
        host.hostnameOrIp = hostname;
    }

    void setPort(final int port) {
        host.port = port;
    }

    void setUserName(@NonNull final String userName) {
        host.userName = userName;
    }

    void setUserPassword(@NonNull final String userPassword) {
        host.userPassword = userPassword;
    }

    void save(@NonNull final ViewModelStoreOwner owner) {
        final EditConfigViewModel cvm = new ViewModelProvider(owner)
                .get(EditConfigViewModel.class);
        db.getExecutor().execute(() -> {
            if (host.id == 0) {
                cvm.setHost((int) db.getHostDao().insert(host));
            } else {
                db.getHostDao().update(host);
            }
        });
    }

    void delete(@NonNull final ViewModelStoreOwner owner) {
        final EditConfigViewModel cvm = new ViewModelProvider(owner)
                .get(EditConfigViewModel.class);
        db.getExecutor().execute(() -> {
            db.getHostDao().delete(host);
            cvm.setHost(0);
        });
    }
}
