package com.hardbackcollector.sshremote;

import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Button;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AppCompatActivity;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.navigation.NavController;
import androidx.navigation.NavHost;
import androidx.navigation.fragment.NavHostFragment;
import androidx.navigation.ui.AppBarConfiguration;
import androidx.navigation.ui.NavigationUI;

import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.hardbackcollector.sshremote.databinding.ActivityMainBinding;

public class MainActivity
        extends AppCompatActivity {

    private AppBarConfiguration appBarConfiguration;
    private ActivityMainBinding mVb;
    private NavController mNavController;
    private BottomSheetBehavior<ConstraintLayout> mBottomSheetBehavior;

    @Override
    protected void onCreate(@Nullable final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        mVb = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(mVb.getRoot());

        setSupportActionBar(mVb.toolbar);

        // https://developer.android.com/guide/navigation/navigation-getting-started#navigate
        // using 'FragmentContainerView'
        final NavHost navHostFragment = (NavHostFragment) getSupportFragmentManager()
                .findFragmentById(R.id.nav_host_fragment_content_main);
        //noinspection ConstantConditions
        mNavController = navHostFragment.getNavController();

        appBarConfiguration = new AppBarConfiguration.Builder(mNavController.getGraph()).build();
        NavigationUI.setupActionBarWithNavController(this, mNavController, appBarConfiguration);

        mBottomSheetBehavior = BottomSheetBehavior.from(mVb.buttonPositions);
        mBottomSheetBehavior.setState(BottomSheetBehavior.STATE_HIDDEN);
    }

    @Override
    public boolean onCreateOptionsMenu(@NonNull final Menu menu) {
        getMenuInflater().inflate(R.menu.menu_activity, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull final MenuItem item) {
        final int itemId = item.getItemId();

        if (itemId == R.id.MENU_ABOUT) {
            new MaterialAlertDialogBuilder(this)
                    .setTitle(R.string.app_name)
                    .setMessage(R.string.menu_about)
                    .create()
                    .show();
            return true;
        }

        return super.onOptionsItemSelected(item);
    }

    @Override
    public boolean onSupportNavigateUp() {
        return NavigationUI.navigateUp(mNavController, appBarConfiguration)
                || super.onSupportNavigateUp();
    }

    public FloatingActionButton getFab() {
        return mVb.scrollUp;
    }

    public BottomSheetBehavior<ConstraintLayout> getBottomSheetBehavior() {
        return mBottomSheetBehavior;
    }

    public Button getBottomSheetButtonSave() {
        return mVb.btnSave;
    }

    public Button getBottomSheetButtonUndo() {
        return mVb.btnUndo;
    }
}
