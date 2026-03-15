package com.hardbacknutter.sshremote;

import android.os.Build;
import android.os.Bundle;
import android.widget.Button;

import androidx.activity.EdgeToEdge;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.fragment.app.FragmentManager;
import androidx.preference.PreferenceManager;

import com.google.android.material.appbar.AppBarLayout;
import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.floatingactionbutton.FloatingActionButton;

import com.hardbacknutter.sshremote.databinding.ActivityMainBinding;

import org.bouncycastle.asn1.ocsp.ServiceLocator;

public class MainActivity
        extends AppCompatActivity {

    /**
     * Preference key: Whether to use scrolling or fixed  system/menu bars.
     * <p>
     * Type: stringified int
     * <p>
     * {@code 0}: scroll
     * {@code 1}: fixed
     */
    public static final String PK_UI_TOP_MENU = "ui.screen.systembars.fixed";

    private ActivityMainBinding vb;
    private BottomSheetBehavior<ConstraintLayout> bottomSheetBehavior;

    /**
     * Check if the system/menu bar should be scrolling or fixed.
     *
     * @return {@code true} for fixed, {@code false} for scrolling
     *
     * @see #applyScrollFlags(Toolbar)
     */
    boolean useFixedHeaderAndFooter() {
        // 0 -> scroll
        // 1 -> fixed
        return 0 != getIntFromString(PK_UI_TOP_MENU, 0);
    }

    /**
     * {@code ListPreference} stores the selected {@code int} value as a {@code String}.
     * This convenience method reads the value as a {@code String}
     * and parses/returns it as an {@code int}.
     *
     * @param key      The name of the preference to retrieve.
     * @param defValue Value to return if this preference does not exist,
     *                 or if the stored value is somehow invalid
     *
     * @return Returns the preference value if it exists, or defValue.
     */
    @SuppressWarnings("SameParameterValue")
    private int getIntFromString(@NonNull final String key,
                                 final int defValue) {
        final String value = PreferenceManager.getDefaultSharedPreferences(this)
                                              .getString(key, null);
        if (value == null || value.isEmpty()) {
            return defValue;
        }

        try {
            return Integer.parseInt(value);
        } catch (@NonNull final NumberFormatException ignore) {
            return defValue;
        }
    }

    /**
     * Apply the scroll flags to the toolbar according to use preferences.
     *
     * @param toolbar to handle
     *
     * @see #useFixedHeaderAndFooter()
     */
    void applyScrollFlags(@NonNull final Toolbar toolbar) {
        final AppBarLayout.LayoutParams lp = (AppBarLayout.LayoutParams)
                toolbar.getLayoutParams();
        if (useFixedHeaderAndFooter()) {
            lp.setScrollFlags(AppBarLayout.LayoutParams.SCROLL_FLAG_NO_SCROLL);
        } else {
            lp.setScrollFlags(AppBarLayout.LayoutParams.SCROLL_FLAG_SCROLL
                              | AppBarLayout.LayoutParams.SCROLL_FLAG_ENTER_ALWAYS
                              | AppBarLayout.LayoutParams.SCROLL_FLAG_SNAP
            );
        }
        toolbar.setLayoutParams(lp);
    }

    @Override
    protected void onCreate(@Nullable final Bundle savedInstanceState) {
        // All insets rely on android:fitsSystemWindows="true"
        // as set on the top CoordinatorLayout.
        // The status-bar will be transparent.
        // Not the "best" look, but more than good enough for this app
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            EdgeToEdge.enable(this);
        }
        super.onCreate(savedInstanceState);

        vb = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(vb.getRoot());

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            getWindow().setNavigationBarContrastEnforced(false);
        }

        applyScrollFlags(vb.toolbar);

        bottomSheetBehavior = BottomSheetBehavior.from(vb.buttonPositions);
        bottomSheetBehavior.setState(BottomSheetBehavior.STATE_HIDDEN);

        final FragmentManager fm = getSupportFragmentManager();
        if (fm.findFragmentByTag(MainFragment.TAG) == null) {
            fm.beginTransaction()
              .setReorderingAllowed(true)
              .add(R.id.main_fragment, new MainFragment(), MainFragment.TAG)
              .commit();
        }
    }

    @NonNull
    FloatingActionButton getFab() {
        return vb.scrollUp;
    }

    @NonNull
    BottomSheetBehavior<ConstraintLayout> getBottomSheetBehavior() {
        return bottomSheetBehavior;
    }

    @NonNull
    Button getBottomSheetButtonSave() {
        return vb.btnSave;
    }

    @NonNull
    Button getBottomSheetButtonUndo() {
        return vb.btnUndo;
    }

    @NonNull
    Toolbar getToolbar() {
        return vb.toolbar;
    }
}
