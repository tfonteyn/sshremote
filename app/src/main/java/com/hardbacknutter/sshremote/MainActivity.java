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

import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.floatingactionbutton.FloatingActionButton;

import com.hardbacknutter.sshremote.databinding.ActivityMainBinding;

public class MainActivity
        extends AppCompatActivity {

    private ActivityMainBinding vb;
    private BottomSheetBehavior<ConstraintLayout> bottomSheetBehavior;

    @Override
    protected void onCreate(@Nullable final Bundle savedInstanceState) {
        // All insets rely on android:fitsSystemWindows="true"
        // as set on the top CoordinatorLayout.
        // The status-bar will be transparent.
        // Not the "best" look, but more then good enough for this app
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            EdgeToEdge.enable(this);
        }
        super.onCreate(savedInstanceState);

        vb = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(vb.getRoot());

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            getWindow().setNavigationBarContrastEnforced(false);
        }

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

    FloatingActionButton getFab() {
        return vb.scrollUp;
    }

    BottomSheetBehavior<ConstraintLayout> getBottomSheetBehavior() {
        return bottomSheetBehavior;
    }

    Button getBottomSheetButtonSave() {
        return vb.btnSave;
    }

    Button getBottomSheetButtonUndo() {
        return vb.btnUndo;
    }

    @NonNull
    Toolbar getToolbar() {
        return vb.toolbar;
    }
}
