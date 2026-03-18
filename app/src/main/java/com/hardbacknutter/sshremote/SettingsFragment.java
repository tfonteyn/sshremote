package com.hardbacknutter.sshremote;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;

import androidx.activity.OnBackPressedCallback;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.Toolbar;
import androidx.preference.ListPreference;
import androidx.preference.Preference;
import androidx.preference.PreferenceFragmentCompat;
import androidx.preference.SeekBarPreference;
import androidx.preference.SwitchPreference;
import androidx.preference.TwoStatePreference;

import com.google.android.material.snackbar.Snackbar;

import com.hardbacknutter.sshclient.Logger;
import com.hardbacknutter.sshremote.ssh.SshHelper;

public class SettingsFragment
        extends PreferenceFragmentCompat
        implements SharedPreferences.OnSharedPreferenceChangeListener {

    static final String TAG = "SettingsFragment";

    /**
     * Default for {@link #PK_BUTTONS_PER_PAGE}.
     */
    static final int DEF_BUTTONS_PER_PAGE = 8;
    /**
     * Orientation.
     * {@code true}: Horizontal.
     * {@code false}: Vertical.
     */
    static final String PK_BUTTONS_FLOW = "global.buttons.flow";
    /**
     * Number of buttons.
     */
    static final String PK_BUTTONS_PER_PAGE = "global.buttons.amount";
    /**
     * Boolean: {@code false}: automatic (resources),
     * or {@code true}: manual from {@link #PK_BUTTONS_SPAN_COUNT}.
     */
    static final String PK_BUTTONS_SPAN = "global.buttons.span";
    /**
     * Used for both columns and rows. Depends on the {@link #PK_BUTTONS_FLOW} setting.
     */
    static final String PK_BUTTONS_SPAN_COUNT = "global.buttons.span.count";
    /**
     * Whether to wrap the output of scroll horizontal.
     */
    static final String PK_WRAP_OUTPUT = "global.output.wrap";

    private final OnBackPressedCallback backPressedCallback =
            new OnBackPressedCallback(true) {
                @Override
                public void handleOnBackPressed() {
                    getParentFragmentManager().popBackStack();
                }
            };

    private SeekBarPreference spanCount;
    private SeekBarPreference logLevelPref;

    @Override
    public void onCreatePreferences(final Bundle savedInstanceState,
                                    final String rootKey) {
        setPreferencesFromResource(R.xml.preferences, rootKey);

        final SwitchPreference buttonsFlow = findPreference(PK_BUTTONS_FLOW);
        //noinspection DataFlowIssue
        buttonsFlow.setSummaryProvider(p -> {
            if (((TwoStatePreference) p).isChecked()) {
                return getString(R.string.vertical);
            } else {
                return getString(R.string.horizontal);
            }
        });

        spanCount = findPreference(PK_BUTTONS_SPAN_COUNT);

        logLevelPref = findPreference(SshHelper.PK_SSH_LOG_LEVEL);
        updateLogLevelSummary();

        initTopMenuBehaviour();
    }

    private void initTopMenuBehaviour() {
        final Preference p = findPreference(MainActivity.PK_UI_TOP_MENU);
        //noinspection DataFlowIssue
        p.setSummaryProvider(ListPreference.SimpleSummaryProvider.getInstance());
        p.setOnPreferenceChangeListener((preference, newValue) -> {
            //noinspection DataFlowIssue
            Snackbar.make(getView(), R.string.warning_requires_restart,
                          Snackbar.LENGTH_LONG).show();
            return true;
        });
    }

    @Override
    public void onStart() {
        super.onStart();

        //noinspection DataFlowIssue
        getPreferenceScreen().getSharedPreferences()
                             .registerOnSharedPreferenceChangeListener(this);
    }

    @Override
    public void onStop() {
        //noinspection DataFlowIssue
        getPreferenceScreen().getSharedPreferences()
                             .unregisterOnSharedPreferenceChangeListener(this);
        super.onStop();
    }

    @Override
    public void onSharedPreferenceChanged(@NonNull final SharedPreferences preferences,
                                          @Nullable final String key) {
        // paranoia
        if (key == null) {
            return;
        }

        switch (key) {
            case PK_BUTTONS_FLOW: {
                final boolean flowHorizontal = preferences.getBoolean(key, false);
                if (flowHorizontal) {
                    spanCount.setTitle(R.string.lbl_columns);
                } else {
                    spanCount.setTitle(R.string.lbl_rows);
                }
                break;
            }
            case SshHelper.PK_SSH_LOG_LEVEL: {
                updateLogLevelSummary();
                break;
            }
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

    @Override
    public void onViewCreated(@NonNull final View view,
                              @Nullable final Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        final Toolbar toolbar = initToolbar();
        toolbar.setSubtitle(R.string.lbl_settings);
    }

    @NonNull
    private Toolbar initToolbar() {
        final MainActivity activity = (MainActivity) getActivity();
        //noinspection DataFlowIssue
        final Toolbar toolbar = activity.getToolbar();
        toolbar.setNavigationIcon(R.drawable.arrow_back_24px);
        toolbar.setNavigationOnClickListener(v -> getParentFragmentManager().popBackStack());

        activity.getOnBackPressedDispatcher()
                .addCallback(getViewLifecycleOwner(), backPressedCallback);
        return toolbar;
    }
}
