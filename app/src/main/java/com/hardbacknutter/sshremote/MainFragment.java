package com.hardbacknutter.sshremote;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.widget.Toolbar;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.util.Pair;
import androidx.core.view.MenuProvider;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;
import androidx.preference.PreferenceManager;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.floatingactionbutton.FloatingActionButton;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import com.hardbacknutter.sshclient.ChannelSession;
import com.hardbacknutter.sshclient.SshClientFactory;
import com.hardbacknutter.sshclient.userauth.SshTooManyAuthAttemptException;
import com.hardbacknutter.sshremote.databinding.ButtonBinding;
import com.hardbacknutter.sshremote.databinding.FragmentMainBinding;
import com.hardbacknutter.sshremote.ddsupport.ItemTouchHelperAdapter;
import com.hardbacknutter.sshremote.ddsupport.SimpleItemTouchHelperCallback;

public class MainFragment
        extends Fragment {

    static final String TAG = "MainFragment";

    private final List<UserButton> list = new ArrayList<>();
    private FragmentMainBinding vb;
    private MainViewModel vm;
    private FloatingActionButton fab;
    private ButtonAdapter adapter;
    private ItemTouchHelper itemTouchHelper;

    private boolean movingButtons;
    private BottomSheetBehavior<ConstraintLayout> bottomSheetBehavior;

    @Override
    public View onCreateView(@NonNull final LayoutInflater inflater,
                             @Nullable final ViewGroup container,
                             @Nullable final Bundle savedInstanceState) {
        vb = FragmentMainBinding.inflate(inflater, container, false);

        final GridLayoutManager lm = (GridLayoutManager) vb.buttonFlow.getLayoutManager();
        Objects.requireNonNull(lm);

        final Context context = inflater.getContext();
        final SharedPreferences preferences =
                PreferenceManager.getDefaultSharedPreferences(context);

        final boolean flowHorizontal = preferences
                .getBoolean(SettingsFragment.PK_BUTTONS_FLOW, false);
        if (flowHorizontal) {
            // android:orientation="horizontal"
            // app:spanCount="@integer/btn_list_column_count"
            // portrait phone: 6 buttons in a column
            // landscape phone: 4 buttons in a column
            lm.setOrientation(RecyclerView.HORIZONTAL);
            lm.setSpanCount(context.getResources().getInteger(R.integer.btn_list_column_count));
        } else {
            // android:orientation="vertical"
            // app:spanCount="@integer/btn_list_row_count"
            // portrait phone: 2 buttons in a row
            // landscape phone: 3 buttons in a row
            lm.setOrientation(RecyclerView.VERTICAL);
            lm.setSpanCount(context.getResources().getInteger(R.integer.btn_list_row_count));
        }

        return vb.getRoot();
    }

    @Override
    public void onViewCreated(@NonNull final View view,
                              @Nullable final Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        final Context context = view.getContext();

        vm = new ViewModelProvider(this).get(MainViewModel.class);
        vm.init(context);
        vm.onConfigLoaded().observe(getViewLifecycleOwner(), this::onConfigLoaded);
        vm.onFinished().observe(getViewLifecycleOwner(), this::onFinished);
        vm.onFailed().observe(getViewLifecycleOwner(), this::onFailed);

        adapter = new ButtonAdapter(context);
        vb.buttonFlow.setAdapter(adapter);

        final SimpleItemTouchHelperCallback sitHelperCallback =
                new SimpleItemTouchHelperCallback(adapter);
        itemTouchHelper = new ItemTouchHelper(sitHelperCallback);
        itemTouchHelper.attachToRecyclerView(vb.buttonFlow);

        vb.clearOutput.setOnClickListener(v -> clearOutput());

        final MainActivity activity = (MainActivity) getActivity();
        //noinspection DataFlowIssue
        bottomSheetBehavior = activity.getBottomSheetBehavior();
        activity.getBottomSheetButtonSave().setOnClickListener(v -> setButtonOrder(true));
        activity.getBottomSheetButtonUndo().setOnClickListener(v -> setButtonOrder(false));

        fab = activity.getFab();
        fab.setOnClickListener(v -> vb.topScroller.scrollTo(0, 0));

        vb.topScroller.setOnScrollChangeListener(
                (View.OnScrollChangeListener) (v, scrollX, scrollY, oldScrollX, oldScrollY)
                        -> fab.setVisibility(scrollY == 0 ? View.INVISIBLE : View.VISIBLE));

        final Toolbar toolbar = activity.getToolbar();
        toolbar.addMenuProvider(new ToolbarMenuProvider(), getViewLifecycleOwner());
        toolbar.setTitle(R.string.app_name);
        toolbar.setSubtitle("");
        toolbar.setNavigationIcon(null);
        toolbar.setNavigationOnClickListener(null);
    }

    private void setButtonOrder(final boolean save) {
        movingButtons = false;
        bottomSheetBehavior.setState(BottomSheetBehavior.STATE_HIDDEN);
        if (save) {
            vm.saveButtonOrder(list);
        } else {
            //noinspection DataFlowIssue
            vm.init(getContext());
        }
    }

    @SuppressLint("NotifyDataSetChanged")
    private void onConfigLoaded(@NonNull final List<UserButton> userButtons) {
        list.clear();
        list.addAll(userButtons);
        adapter.notifyDataSetChanged();
    }

    private void clearOutput() {
        vb.lastButton.setText("");
        vb.lastExitCode.setText("");
        vb.output.setText("");
        vb.clearOutput.setVisibility(View.INVISIBLE);
    }

    private void edit(final int buttonId) {
        final Bundle args = new Bundle();
        args.putInt(EditButtonViewModel.ARGS_BUTTON_POSITION, buttonId);
        final EditButtonFragment fragment = new EditButtonFragment();
        fragment.setArguments(args);
        getParentFragmentManager()
                .beginTransaction()
                .setReorderingAllowed(true)
                .addToBackStack(EditButtonFragment.TAG)
                .replace(R.id.main_fragment, fragment, EditButtonFragment.TAG)
                .commit();
    }

    private void onFinished(@NonNull final FinishedMessage<UserButton> result) {
        vb.progress.setVisibility(View.GONE);

        if (result.isNewEvent()) {
            final UserButton userButton = result.getResult();
            //noinspection DataFlowIssue
            final ChannelSession.ExitStatus exitStatus = userButton.getExitStatus();
            if (exitStatus == null) {
                vb.lastExitCode.setVisibility(View.INVISIBLE);
            } else {
                if (exitStatus.getStatus() == -1) {
                    vb.lastExitCode.setVisibility(View.INVISIBLE);
                } else if (exitStatus.getStatus() == 0) {
                    vb.lastExitCode.setVisibility(View.INVISIBLE);
                } else {
                    vb.lastExitCode.setVisibility(View.VISIBLE);
                    String s = "(" + exitStatus.getStatus() + ")";
                    if (exitStatus.getMessage() != null) {
                        s += exitStatus.getMessage();
                    }
                    vb.lastExitCode.setText(s);
                }
            }
            vb.lastButton.setText(userButton.getLabel());
            vb.output.setText(userButton.getOutput());
            vb.clearOutput.setVisibility(View.VISIBLE);
        }
    }

    private void onFailed(@NonNull final Pair<FinishedMessage<UserButton>, Exception> result) {
        vb.progress.setVisibility(View.GONE);

        if (result.first.isNewEvent()) {
            final UserButton userButton = result.first.getResult();
            final Exception e = result.second;

            //noinspection DataFlowIssue
            vb.lastButton.setText(userButton.getLabel());
            vb.lastExitCode.setVisibility(View.INVISIBLE);

            vb.clearOutput.setVisibility(View.VISIBLE);

            if (e instanceof UnknownHostException) {
                vb.output.setText(R.string.error_ping_failed);

            }
            if (e instanceof SshTooManyAuthAttemptException) {
                vb.output.setText(getString(R.string.error_to_many_auth,
                                            ((SshTooManyAuthAttemptException) e).getAuthTries()));
            } else {
                vb.output.setText(e.getMessage());
            }
        }
    }

    public static class Holder
            extends RecyclerView.ViewHolder {

        @NonNull
        private final ButtonBinding mVb;

        Holder(@NonNull final View itemView) {
            super(itemView);
            mVb = ButtonBinding.bind(itemView);
        }
    }

    public class ButtonAdapter
            extends RecyclerView.Adapter<Holder>
            implements ItemTouchHelperAdapter {

        @NonNull

        private final LayoutInflater mLayoutInflater;

        ButtonAdapter(@NonNull final Context context) {
            mLayoutInflater = LayoutInflater.from(context);
        }

        @NonNull
        @Override
        public Holder onCreateViewHolder(@NonNull final ViewGroup parent,
                                         final int viewType) {
            final View view = mLayoutInflater.inflate(R.layout.button, parent, false);
            return new Holder(view);
        }

        @Override
        public void onBindViewHolder(@NonNull final Holder holder,
                                     final int position) {
            final UserButton userButton = list.get(position);
            final String label = userButton.getLabel();
            if (label.isEmpty()) {
                holder.mVb.action.setText(R.string.button_not_set);
            } else {
                holder.mVb.action.setText(label);
            }

            holder.mVb.action.setOnClickListener(v -> {
                if (userButton.isPersisted()) {
                    clearOutput();
                    vb.progress.setVisibility(View.VISIBLE);
                    //noinspection DataFlowIssue
                    vm.execute(getContext(), userButton);
                } else {
                    edit(userButton.getPosition());
                }
            });
            holder.mVb.action.setOnLongClickListener(v -> {
                if (movingButtons) {
                    itemTouchHelper.startDrag(holder);
                } else {
                    edit(userButton.getPosition());
                }
                return true;
            });
        }

        @Override
        public int getItemCount() {
            return list.size();
        }

        /**
         * Note that we're changing the position of the item every time the
         * view is shifted to a new index, and not at the end of a “drop” event.
         *
         * @param fromPosition The start position of the moved item.
         * @param toPosition   The resolved position of the moved item.
         *
         * @return {@code true} if a move was done, {@code false} if not.
         */
        @Override
        public boolean onItemMove(final int fromPosition,
                                  final int toPosition) {
            final UserButton userButtonFrom = list.get(fromPosition);
            final UserButton userButtonTo = list.get(toPosition);

            userButtonFrom.setPosition(toPosition);
            userButtonTo.setPosition(fromPosition);

            Collections.swap(list, fromPosition, toPosition);
            notifyItemMoved(fromPosition, toPosition);
            return true;
        }
    }

    private class ToolbarMenuProvider
            implements MenuProvider {

        @Override
        public void onCreateMenu(@NonNull final Menu menu,
                                 @NonNull final MenuInflater menuInflater) {
            menuInflater.inflate(R.menu.menu_main, menu);
        }

        @Override
        public boolean onMenuItemSelected(@NonNull final MenuItem menuItem) {
            final int itemId = menuItem.getItemId();

            if (itemId == R.id.MENU_GLOBAL_SETTINGS) {
                getParentFragmentManager()
                        .beginTransaction()
                        .setReorderingAllowed(true)
                        .addToBackStack(SettingsFragment.TAG)
                        .replace(R.id.main_fragment, new SettingsFragment(), SettingsFragment.TAG)
                        .commit();
                return true;

            } else if (itemId == R.id.MENU_KEY_MANAGEMENT) {
                getParentFragmentManager()
                        .beginTransaction()
                        .setReorderingAllowed(true)
                        .addToBackStack(KeyManagementFragment.TAG)
                        .replace(R.id.main_fragment,
                                 new KeyManagementFragment(),
                                 KeyManagementFragment.TAG)
                        .commit();
                return true;

            } else if (itemId == R.id.MENU_EDIT_BUTTON_ORDER) {
                movingButtons = true;
                bottomSheetBehavior.setState(BottomSheetBehavior.STATE_EXPANDED);

            } else if (itemId == R.id.MENU_ABOUT) {
                final Context context = requireContext();

                String message;
                try {
                    final PackageInfo pInfo = context.getPackageManager().getPackageInfo(
                            context.getPackageName(), 0);
                    message = getString(R.string.app_name) + ": "
                              + pInfo.versionName
                              + '\n'
                              + getString(R.string.library_name) + ": "
                              + SshClientFactory.getVersionName();

                } catch (@NonNull final PackageManager.NameNotFoundException e) {
                    message = "";
                }

                new MaterialAlertDialogBuilder(context)
                        .setTitle(R.string.app_name)
                        .setMessage(message)
                        .create()
                        .show();
                return true;
            }

            return false;
        }
    }
}
