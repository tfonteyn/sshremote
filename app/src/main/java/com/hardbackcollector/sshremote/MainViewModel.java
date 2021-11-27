package com.hardbackcollector.sshremote;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.annotation.NonNull;
import androidx.core.util.Pair;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModel;
import androidx.preference.PreferenceManager;

import com.hardbackcollector.sshclient.utils.SshException;
import com.hardbackcollector.sshremote.db.DB;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

@SuppressWarnings("WeakerAccess")
public class MainViewModel
        extends ViewModel {

    private final MutableLiveData<List<UserButton>> mUserButtons = new MutableLiveData<>();
    private final MutableLiveData<FinishedMessage<UserButton>>
            mFinished = new MutableLiveData<>();
    private final MutableLiveData<Pair<FinishedMessage<UserButton>, Exception>>
            mFailed = new MutableLiveData<>();

    private DB mDb;

    private int mButtonsPerPage;

    void init(@NonNull final Context context) {
        if (mDb == null) {
            mDb = DB.getInstance(context);
        }

        final SharedPreferences global = PreferenceManager
                .getDefaultSharedPreferences(context);
        mButtonsPerPage = global.getInt(SettingsFragment.PK_BUTTONS_PER_PAGE,
                SettingsFragment.DEF_BUTTONS_PER_PAGE);
        // always refresh
        mDb.getExecutor().execute(() -> {
            final List<UserButton> list = new ArrayList<>();
            for (int i = 0; i < mButtonsPerPage; i++) {
                list.add(new UserButton(mDb, i));
            }
            mUserButtons.postValue(list);
        });
    }

    @NonNull
    LiveData<List<UserButton>> onConfigLoaded() {
        return mUserButtons;
    }

    void execute(@NonNull final Context context,
                 @NonNull final UserButton userButton) {

        final Context appContext = context.getApplicationContext();
        mDb.getExecutor().execute(() -> {
            try {
                userButton.exec(appContext);
                mFinished.postValue(new FinishedMessage<>(0, userButton));
            } catch (final SshException | IOException | GeneralSecurityException e) {
                mFailed.postValue(new Pair<>(new FinishedMessage<>(0, userButton), e));
            }
        });
    }

    @NonNull
    LiveData<FinishedMessage<UserButton>> onFinished() {
        return mFinished;
    }

    @NonNull
    LiveData<Pair<FinishedMessage<UserButton>, Exception>> onFailed() {
        return mFailed;
    }

    public void saveButtonOrder(@NonNull final List<UserButton> list) {
        mDb.getExecutor().execute(() -> list.forEach(userButton -> userButton.update(mDb)));
    }
}
