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

import com.hardbackcollector.sshremote.db.DB;
import com.hardbackcollector.sshremote.db.Host;

@SuppressWarnings("WeakerAccess")
public class EditHostViewModel
        extends ViewModel {

    static final String ARGS_ID = "id";

    private final MutableLiveData<Host> mHostLoaded = new MutableLiveData<>();

    private Host mHost;
    private DB mDb;

    void init(@NonNull final Context context,
              @Nullable final Bundle args) {
        if (mDb == null) {
            mDb = DB.getInstance(context);

            final int id = args == null ? 0 : args.getInt(ARGS_ID, 0);
            Log.d("host", "id=" + id);
            if (id > 0) {
                mDb.getExecutor().execute(() -> {
                    mHost = mDb.getHostDao().findById(id);
                    mHostLoaded.postValue(mHost);
                });
            } else {
                mHost = new Host();
                mHostLoaded.setValue(mHost);
            }
        }
    }

    @NonNull
    LiveData<Host> onConfigLoaded() {
        return mHostLoaded;
    }

    void setLabel(@NonNull final String label) {
        mHost.label = label;
    }

    void setHost(@NonNull final String hostname) {
        mHost.hostnameOrIp = hostname;
    }

    void setPort(final int port) {
        mHost.port = port;
    }

    void setUserName(@NonNull final String userName) {
        mHost.userName = userName;
    }

    void setUserPassword(@NonNull final String userPassword) {
        mHost.userPassword = userPassword;
    }

    void save(@NonNull final ViewModelStoreOwner owner) {
        final EditConfigViewModel cvm = new ViewModelProvider(owner)
                .get(EditConfigViewModel.class);
        mDb.getExecutor().execute(() -> {
            if (mHost.id == 0) {
                cvm.setHost((int) mDb.getHostDao().insert(mHost));
            } else {
                mDb.getHostDao().update(mHost);
            }
        });
    }

    void delete(@NonNull final ViewModelStoreOwner owner) {
        final EditConfigViewModel cvm = new ViewModelProvider(owner)
                .get(EditConfigViewModel.class);
        mDb.getExecutor().execute(() -> {
            mDb.getHostDao().delete(mHost);
            cvm.setHost(0);
        });
    }
}
