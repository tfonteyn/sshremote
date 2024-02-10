package com.hardbacknutter.sshremote;

import android.content.Context;
import android.content.SharedPreferences;

import androidx.annotation.NonNull;
import androidx.core.util.Pair;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;
import androidx.lifecycle.ViewModel;
import androidx.preference.PreferenceManager;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.List;

import com.hardbacknutter.sshclient.utils.SshException;
import com.hardbacknutter.sshremote.db.DB;

@SuppressWarnings("WeakerAccess")
public class MainViewModel
        extends ViewModel {

    private final MutableLiveData<List<UserButton>> userButtons = new MutableLiveData<>();
    private final MutableLiveData<FinishedMessage<UserButton>>
            finished = new MutableLiveData<>();
    private final MutableLiveData<Pair<FinishedMessage<UserButton>, Exception>>
            failed = new MutableLiveData<>();

    private DB db;

    private int buttonsPerPage;

    void init(@NonNull final Context context) {
        if (db == null) {
            db = DB.getInstance(context);
        }

        final SharedPreferences global = PreferenceManager
                .getDefaultSharedPreferences(context);
        buttonsPerPage = global.getInt(SettingsFragment.PK_BUTTONS_PER_PAGE,
                                       SettingsFragment.DEF_BUTTONS_PER_PAGE);
        // always refresh
        db.getExecutor().execute(() -> {
            final List<UserButton> list = new ArrayList<>();
            for (int i = 0; i < buttonsPerPage; i++) {
                list.add(new UserButton(db, i));
            }
            userButtons.postValue(list);
        });
    }

    @NonNull
    LiveData<List<UserButton>> onConfigLoaded() {
        return userButtons;
    }

    void execute(@NonNull final Context context,
                 @NonNull final UserButton userButton) {

        final Context appContext = context.getApplicationContext();
        db.getExecutor().execute(() -> {
            try {
                userButton.exec(appContext);
                finished.postValue(new FinishedMessage<>(0, userButton));
            } catch (final SshException | IOException | GeneralSecurityException e) {
                failed.postValue(new Pair<>(new FinishedMessage<>(0, userButton), e));
            }
        });
    }

    @NonNull
    LiveData<FinishedMessage<UserButton>> onFinished() {
        return finished;
    }

    @NonNull
    LiveData<Pair<FinishedMessage<UserButton>, Exception>> onFailed() {
        return failed;
    }

    public void saveButtonOrder(@NonNull final List<UserButton> list) {
        db.getExecutor().execute(() -> list.forEach(userButton -> userButton.update(db)));
    }
}
