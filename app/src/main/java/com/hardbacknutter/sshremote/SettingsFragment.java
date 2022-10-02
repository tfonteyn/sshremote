package com.hardbacknutter.sshremote;

import android.content.SharedPreferences;
import android.os.Bundle;

import androidx.annotation.NonNull;
import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.SeekBarPreference;
import androidx.preference.SwitchPreference;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshremote.ssh.SshHelper;

public class SettingsFragment
        extends PreferenceFragmentCompat
        implements SharedPreferences.OnSharedPreferenceChangeListener {

    public static final int DEF_BUTTONS_PER_PAGE = 8;
    public static final String PK_BUTTONS_FLOW = "global.buttons.flow";

    public static final String PK_BUTTONS_PER_PAGE = "global.buttons.amount";

    private SeekBarPreference logLevelPref;

    @Override
    public void onCreatePreferences(final Bundle savedInstanceState,
                                    final String rootKey) {
        setPreferencesFromResource(R.xml.global, rootKey);

        final SwitchPreference buttonsFlow = findPreference(PK_BUTTONS_FLOW);

        //noinspection ConstantConditions
        buttonsFlow.setSummaryProvider(p -> {
            if (((SwitchPreference) p).isChecked()) {
                return getString(R.string.vertical);
            } else {
                return getString(R.string.horizontal);
            }
        });

        //noinspection ConstantConditions
        logLevelPref = findPreference(SshHelper.PK_SSH_LOG_LEVEL);
        updateLogLevelSummary();
    }

    @Override
    public void onStart() {
        super.onStart();

        //noinspection ConstantConditions
        getPreferenceScreen().getSharedPreferences()
                             .registerOnSharedPreferenceChangeListener(this);
    }

    @Override
    public void onStop() {
        //noinspection ConstantConditions
        getPreferenceScreen().getSharedPreferences()
                             .unregisterOnSharedPreferenceChangeListener(this);
        super.onStop();
    }

    @Override
    public void onSharedPreferenceChanged(@NonNull final SharedPreferences preferences,
                                          @NonNull final String key) {

        if (SshHelper.PK_SSH_LOG_LEVEL.equals(key)) {
            updateLogLevelSummary();
        }
    }

    private void updateLogLevelSummary() {
        final int level = logLevelPref.getValue();
        // sanity check - It should never be incorrect...
        if (level >= Logger.NONE && level <= Logger.DEBUG) {
            logLevelPref.setSummary(getResources().getStringArray(R.array.log_levels)[level]);
        } else {
            logLevelPref.setSummary(getString(R.string.error_import_failed));
        }
    }
}
