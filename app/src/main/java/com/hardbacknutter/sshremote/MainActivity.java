package com.hardbacknutter.sshremote;

import android.os.Bundle;
import android.widget.Button;

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
        super.onCreate(savedInstanceState);

        vb = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(vb.getRoot());

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
