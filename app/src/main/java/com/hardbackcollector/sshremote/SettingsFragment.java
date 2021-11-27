package com.hardbackcollector.sshremote;

import android.os.Bundle;

import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.SwitchPreference;

import java.util.Objects;

public class SettingsFragment
        extends PreferenceFragmentCompat {

    public static final String PK_STRICT_HOST_KEY_CHECKING = "global.strictHostKeyChecking";

    public static final int DEF_BUTTONS_PER_PAGE = 8;
    public static final String PK_BUTTONS_FLOW = "global.buttons.flow";

    public static final String PK_BUTTONS_PER_PAGE = "global.buttons.amount";

    @Override
    public void onCreatePreferences(final Bundle savedInstanceState,
                                    final String rootKey) {
        setPreferencesFromResource(R.xml.global, rootKey);

        final SwitchPreference buttonsFlow =
                Objects.requireNonNull(findPreference(PK_BUTTONS_FLOW));

        buttonsFlow.setSummaryProvider(p -> {
            if (((SwitchPreference) p).isChecked()) {
                return getString(R.string.vertical);
            } else {
                return getString(R.string.horizontal);
            }
        });
    }
}
