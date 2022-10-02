package com.hardbacknutter.sshremote;

import android.content.Context;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.constraintlayout.widget.ConstraintLayout;
import androidx.core.util.Pair;
import androidx.core.view.MenuProvider;
import androidx.lifecycle.ViewModelProvider;
import androidx.navigation.NavController;
import androidx.navigation.fragment.NavHostFragment;
import androidx.preference.PreferenceManager;
import androidx.recyclerview.widget.GridLayoutManager;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.bottomsheet.BottomSheetBehavior;
import com.google.android.material.floatingactionbutton.FloatingActionButton;
import com.hardbacknutter.sshclient.ChannelSession;
import com.hardbacknutter.sshclient.userauth.SshTooManyAuthAttemptException;
import com.hardbacknutter.sshremote.databinding.ButtonBinding;
import com.hardbacknutter.sshremote.databinding.FragmentMainBinding;
import com.hardbacknutter.sshremote.ddsupport.ItemTouchHelperAdapter;
import com.hardbacknutter.sshremote.ddsupport.SimpleItemTouchHelperCallback;

import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class MainFragment
        extends BaseFragment {

    private final List<UserButton> mList = new ArrayList<>();
    private FragmentMainBinding mVb;
    private MainViewModel mVm;
    private NavController mNavController;
    private FloatingActionButton mFab;
    private ButtonAdapter mAdapter;
    private ItemTouchHelper mItemTouchHelper;

    private boolean mMovingButtons;
    private BottomSheetBehavior<ConstraintLayout> mBottomSheetBehavior;

    @Override
    public View onCreateView(@NonNull final LayoutInflater inflater,
                             @Nullable final ViewGroup container,
                             @Nullable final Bundle savedInstanceState) {
        mVb = FragmentMainBinding.inflate(inflater, container, false);

        final GridLayoutManager lm = (GridLayoutManager) mVb.buttonFlow.getLayoutManager();
        Objects.requireNonNull(lm);

        final Context context = inflater.getContext();
        final SharedPreferences global = PreferenceManager.getDefaultSharedPreferences(context);

        final boolean flowHorizontal = global.getBoolean(SettingsFragment.PK_BUTTONS_FLOW, false);
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

        return mVb.getRoot();
    }

    @Override
    public void onViewCreated(@NonNull final View view,
                              @Nullable final Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);
        final Context context = view.getContext();

        mNavController = NavHostFragment.findNavController(this);

        mVm = new ViewModelProvider(this).get(MainViewModel.class);
        mVm.init(context);
        mVm.onConfigLoaded().observe(getViewLifecycleOwner(), this::onConfigLoaded);
        mVm.onFinished().observe(getViewLifecycleOwner(), this::onFinished);
        mVm.onFailed().observe(getViewLifecycleOwner(), this::onFailed);

        mAdapter = new ButtonAdapter(context);
        mVb.buttonFlow.setAdapter(mAdapter);

        final SimpleItemTouchHelperCallback sitHelperCallback =
                new SimpleItemTouchHelperCallback(mAdapter);
        mItemTouchHelper = new ItemTouchHelper(sitHelperCallback);
        mItemTouchHelper.attachToRecyclerView(mVb.buttonFlow);

        mVb.clearOutput.setOnClickListener(v -> clearOutput());

        final MainActivity activity = (MainActivity) getActivity();
        //noinspection ConstantConditions
        mBottomSheetBehavior = activity.getBottomSheetBehavior();
        activity.getBottomSheetButtonSave().setOnClickListener(v -> setButtonOrder(true));
        activity.getBottomSheetButtonUndo().setOnClickListener(v -> setButtonOrder(false));

        mFab = activity.getFab();
        mFab.setOnClickListener(v -> mVb.topScroller.scrollTo(0, 0));

        mVb.topScroller.setOnScrollChangeListener(
                (View.OnScrollChangeListener) (v, scrollX, scrollY, oldScrollX, oldScrollY)
                        -> mFab.setVisibility(scrollY == 0 ? View.INVISIBLE : View.VISIBLE));

        getToolbar().addMenuProvider(new ToolbarMenuProvider(), getViewLifecycleOwner());
    }

    private void setButtonOrder(final boolean save) {
        mMovingButtons = false;
        mBottomSheetBehavior.setState(BottomSheetBehavior.STATE_HIDDEN);
        if (save) {
            mVm.saveButtonOrder(mList);
        } else {
            //noinspection ConstantConditions
            mVm.init(getContext());
        }
    }

    private void onConfigLoaded(@NonNull final List<UserButton> userButtons) {
        mList.clear();
        mList.addAll(userButtons);
        mAdapter.notifyDataSetChanged();
    }

    private void clearOutput() {
        mVb.lastButton.setText("");
        mVb.lastExitCode.setText("");
        mVb.output.setText("");
        mVb.clearOutput.setVisibility(View.INVISIBLE);
    }

    private void edit(final int buttonId) {
        final Bundle args = new Bundle();
        args.putInt(EditConfigViewModel.ARGS_BUTTON_POSITION, buttonId);
        mNavController.navigate(R.id.action_MainFragment_to_EditConfigFragment, args);
    }

    private void onFinished(@NonNull final FinishedMessage<UserButton> result) {
        mVb.progress.setVisibility(View.GONE);

        if (result.isNewEvent()) {
            final UserButton userButton = result.getResult();
            //noinspection ConstantConditions
            final ChannelSession.ExitStatus exitStatus = userButton.getExitStatus();
            if (exitStatus == null) {
                mVb.lastExitCode.setVisibility(View.INVISIBLE);
            } else {
                if (exitStatus.getStatus() == -1) {
                    mVb.lastExitCode.setVisibility(View.INVISIBLE);
                } else if (exitStatus.getStatus() == 0) {
                    mVb.lastExitCode.setVisibility(View.INVISIBLE);
                } else {
                    mVb.lastExitCode.setVisibility(View.VISIBLE);
                    String s = "(" + exitStatus.getStatus() + ")";
                    if (exitStatus.getMessage() != null) {
                        s += exitStatus.getMessage();
                    }
                    mVb.lastExitCode.setText(s);
                }
            }
            mVb.lastButton.setText(userButton.getLabel());
            mVb.output.setText(userButton.getOutput());
            mVb.clearOutput.setVisibility(View.VISIBLE);
        }
    }

    private void onFailed(@NonNull final Pair<FinishedMessage<UserButton>, Exception> result) {
        mVb.progress.setVisibility(View.GONE);

        if (result.first.isNewEvent()) {
            final UserButton userButton = result.first.getResult();
            final Exception e = result.second;

            //noinspection ConstantConditions
            mVb.lastButton.setText(userButton.getLabel());
            mVb.lastExitCode.setVisibility(View.INVISIBLE);

            mVb.clearOutput.setVisibility(View.VISIBLE);

            if (e instanceof UnknownHostException) {
                mVb.output.setText(R.string.error_ping_failed);

            }
            if (e instanceof SshTooManyAuthAttemptException) {
                mVb.output.setText(getString(R.string.error_to_many_auth,
                        ((SshTooManyAuthAttemptException) e).getAuthTries()));
            } else {
                mVb.output.setText(e.getMessage());
            }
        }
    }

    private static class Holder
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
            final UserButton userButton = mList.get(position);
            final String label = userButton.getLabel();
            if (label.isEmpty()) {
                holder.mVb.action.setText(R.string.button_not_set);
            } else {
                holder.mVb.action.setText(label);
            }

            holder.mVb.action.setOnClickListener(v -> {
                if (userButton.isPersisted()) {
                    clearOutput();
                    mVb.progress.setVisibility(View.VISIBLE);
                    //noinspection ConstantConditions
                    mVm.execute(getContext(), userButton);
                } else {
                    edit(userButton.getPosition());
                }
            });
            holder.mVb.action.setOnLongClickListener(v -> {
                if (mMovingButtons) {
                    mItemTouchHelper.startDrag(holder);
                } else {
                    edit(userButton.getPosition());
                }
                return true;
            });
        }

        @Override
        public int getItemCount() {
            return mList.size();
        }

        /**
         * Note that we're changing the position of the item every time the
         * view is shifted to a new index, and not at the end of a “drop” event.
         *
         * @param fromPosition The start position of the moved item.
         * @param toPosition   The resolved position of the moved item.
         * @return {@code true} if a move was done, {@code false} if not.
         */
        @Override
        public boolean onItemMove(final int fromPosition,
                                  final int toPosition) {
            final UserButton userButtonFrom = mList.get(fromPosition);
            final UserButton userButtonTo = mList.get(toPosition);

            userButtonFrom.setPosition(toPosition);
            userButtonTo.setPosition(fromPosition);

            Collections.swap(mList, fromPosition, toPosition);
            notifyItemMoved(fromPosition, toPosition);
            return true;
        }
    }

    private class ToolbarMenuProvider implements MenuProvider {

        @Override
        public void onCreateMenu(@NonNull final Menu menu,
                                 @NonNull final MenuInflater menuInflater) {
            menuInflater.inflate(R.menu.menu_main, menu);
        }

        @Override
        public boolean onMenuItemSelected(@NonNull final MenuItem menuItem) {
            final int itemId = menuItem.getItemId();

            if (itemId == R.id.MENU_GLOBAL_SETTINGS) {
                mNavController.navigate(R.id.action_mainFragment_to_settingsFragment);
                return true;

            } else if (itemId == R.id.MENU_KEY_MANAGEMENT) {
                mNavController.navigate(R.id.action_mainFragment_to_keyManagementFragment);
                return true;

            } else if (itemId == R.id.MENU_EDIT_BUTTON_ORDER) {
                mMovingButtons = true;
                mBottomSheetBehavior.setState(BottomSheetBehavior.STATE_EXPANDED);
            }
            return false;
        }
    }
}
