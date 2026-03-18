package com.hardbacknutter.sshremote;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.util.DisplayMetrics;
import android.util.TypedValue;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.ScaleGestureDetector;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.MimeTypeMap;
import android.widget.TextView;

import androidx.activity.result.ActivityResultLauncher;
import androidx.annotation.Dimension;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.Px;
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
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import com.hardbacknutter.sshclient.ChannelSession;
import com.hardbacknutter.sshclient.SshClientFactory;
import com.hardbacknutter.sshclient.userauth.SshTooManyAuthAttemptException;
import com.hardbacknutter.sshremote.databinding.FragmentMainBinding;
import com.hardbacknutter.sshremote.databinding.RowButtonBinding;
import com.hardbacknutter.sshremote.db.Host;
import com.hardbacknutter.sshremote.ddsupport.ItemTouchHelperAdapter;
import com.hardbacknutter.sshremote.ddsupport.SimpleItemTouchHelperCallback;
import com.hardbacknutter.sshremote.debug.GetContentUriForWritingContract;

public class MainFragment
        extends Fragment {

    static final String TAG = "MainFragment";

    private final List<UserButton> list = new ArrayList<>();
    private FragmentMainBinding vb;
    private MainViewModel vm;

    /** The launcher for picking a Uri to write to. */
    @SuppressWarnings("DataFlowIssue")
    private final ActivityResultLauncher<GetContentUriForWritingContract.Input>
            createDocumentLauncher = registerForActivityResult(
            new GetContentUriForWritingContract(),
            o -> o.ifPresent(uri -> vm.writeDebugFile(getContext(), uri)));

    private ScaleGestureDetector scaleGestureDetector;

    private FloatingActionButton fab;
    private ButtonAdapter adapter;
    private ItemTouchHelper itemTouchHelper;

    private boolean movingButtons;
    private BottomSheetBehavior<ConstraintLayout> bottomSheetBehavior;
    private TextView outputView;

    @Override
    public View onCreateView(@NonNull final LayoutInflater inflater,
                             @Nullable final ViewGroup container,
                             @Nullable final Bundle savedInstanceState) {
        vb = FragmentMainBinding.inflate(inflater, container, false);

        final GridLayoutManager lm = (GridLayoutManager) vb.buttonFlow.getLayoutManager();
        Objects.requireNonNull(lm);
        selectButtonOrientationAndSpan(inflater.getContext(), lm);

        selectOutputView();
        return vb.getRoot();
    }

    private void selectButtonOrientationAndSpan(@NonNull final Context context,
                                                @NonNull final GridLayoutManager lm) {

        final SharedPreferences preferences =
                PreferenceManager.getDefaultSharedPreferences(context);

        final boolean flowHorizontal = preferences
                .getBoolean(SettingsFragment.PK_BUTTONS_FLOW, false);
        final int spanResId;
        if (flowHorizontal) {
            // android:orientation="horizontal"
            // app:spanCount="@integer/btn_list_column_count"
            // portrait phone: 6 buttons in a column
            // landscape phone: 3 buttons in a column
            lm.setOrientation(RecyclerView.HORIZONTAL);
            spanResId = R.integer.btn_list_column_count;
        } else {
            // android:orientation="vertical"
            // app:spanCount="@integer/btn_list_row_count"
            // portrait phone: 2 buttons in a row
            // landscape phone: 3 buttons in a row
            lm.setOrientation(RecyclerView.VERTICAL);
            spanResId = R.integer.btn_list_row_count;
        }

        final boolean spanManual = preferences.getBoolean(SettingsFragment.PK_BUTTONS_SPAN, false);
        if (spanManual) {
            final int spanCount = preferences.getInt(SettingsFragment.PK_BUTTONS_SPAN_COUNT, 2);
            lm.setSpanCount(spanCount);
        } else {
            lm.setSpanCount(context.getResources().getInteger(spanResId));
        }
    }

    /**
     * Flip visibility between wrapped and scrollable view.
     * <p>
     * There are "solutions" on the internet which make a TextView scroll,
     * and others which make a HorizontalScrollView not-scroll.
     * They have in common that none of them work properly....
     * So, we just swap two views instead, easy, reliable.
     */
    @SuppressLint("ClickableViewAccessibility")
    private void selectOutputView() {
        final CharSequence text;
        if (isWrap()) {
            vb.outputWrapped.setVisibility(View.VISIBLE);
            vb.horScroll.setVisibility(View.GONE);

            text = vb.outputScrollable.getText();
            vb.outputScrollable.setText(null);
            vb.outputScrollable.setOnTouchListener(null);

            outputView = vb.outputWrapped;

        } else {
            vb.outputWrapped.setVisibility(View.GONE);
            vb.horScroll.setVisibility(View.VISIBLE);

            text = vb.outputWrapped.getText();
            vb.outputWrapped.setText(null);
            vb.outputWrapped.setOnTouchListener(null);

            outputView = vb.outputScrollable;
        }
        outputView.setText(text);

        //noinspection DataFlowIssue
        scaleGestureDetector = new ScaleGestureDetector(
                getContext(), new PinchListener(outputView, getResources().getDisplayMetrics()));

        outputView.setClickable(true);
        outputView.setFocusable(true);
        outputView.setOnTouchListener((v, event) -> {
            // If there is more than one finger, disable scrolling/parent interception
            if (event.getPointerCount() > 1) {
                v.getParent().requestDisallowInterceptTouchEvent(true);
            }
            scaleGestureDetector.onTouchEvent(event);
            return true;
        });
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
        vm.onShowProgress().observe(getViewLifecycleOwner(), visible ->
                vb.progress.setVisibility(visible ? View.VISIBLE : View.GONE));

        adapter = new ButtonAdapter(context);
        vb.buttonFlow.setAdapter(adapter);

        final SimpleItemTouchHelperCallback sitHelperCallback =
                new SimpleItemTouchHelperCallback(adapter);
        itemTouchHelper = new ItemTouchHelper(sitHelperCallback);
        itemTouchHelper.attachToRecyclerView(vb.buttonFlow);

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

        initToolbar(activity);
    }

    private void initToolbar(@NonNull final MainActivity activity) {
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
        outputView.setText("");
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
            outputView.setText(userButton.getOutput());
        }
    }

    @SuppressWarnings("ChainOfInstanceofChecks")
    private void onFailed(@NonNull final Pair<FinishedMessage<UserButton>, Exception> result) {
        if (result.first.isNewEvent()) {
            final UserButton userButton = result.first.getResult();
            final Exception e = result.second;

            //noinspection DataFlowIssue
            vb.lastButton.setText(userButton.getLabel());
            vb.lastExitCode.setVisibility(View.INVISIBLE);

            final String msg;
            if (e instanceof UnknownHostException) {
                final Host host = userButton.getHost();
                if (host != null) {
                    msg = getString(R.string.error_unknown_host, host.hostnameOrIp);
                } else {
                    // We should never get here... flw
                    msg = getString(R.string.button_not_set);
                }
            } else if (e instanceof SshTooManyAuthAttemptException) {
                msg = getString(R.string.error_to_many_auth,
                                ((SshTooManyAuthAttemptException) e).getAuthTries());
            } else {
                msg = e.getMessage();
            }
            outputView.setText(msg);
        }
    }

    private boolean isWrap() {
        //noinspection DataFlowIssue
        return PreferenceManager.getDefaultSharedPreferences(
                getContext()).getBoolean(SettingsFragment.PK_WRAP_OUTPUT, true);
    }

    private void toggleWrap() {
        //noinspection DataFlowIssue
        final SharedPreferences prefs = PreferenceManager
                .getDefaultSharedPreferences(getContext());
        final boolean current = !prefs.getBoolean(SettingsFragment.PK_WRAP_OUTPUT, true);
        prefs.edit()
             .putBoolean(SettingsFragment.PK_WRAP_OUTPUT, current)
             .apply();
    }

    public static class Holder
            extends RecyclerView.ViewHolder {

        @NonNull
        private final RowButtonBinding vb;

        Holder(@NonNull final RowButtonBinding vb) {
            super(vb.getRoot());
            this.vb = vb;
        }
    }

    private static final class PinchListener
            extends ScaleGestureDetector.SimpleOnScaleGestureListener {

        @Dimension(unit = Dimension.SP)
        private static final float MIN_SIZE_SP = 8f;
        @Dimension(unit = Dimension.SP)
        private static final float MAX_SIZE_SP = 40f;
        @Px
        final float minSizePx;
        @Px
        final float maxSizePx;
        @NonNull
        private final TextView textView;

        private PinchListener(@NonNull final TextView textView,
                              @NonNull final DisplayMetrics metrics) {
            this.textView = textView;
            minSizePx = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, MIN_SIZE_SP,
                                                  metrics);
            maxSizePx = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, MAX_SIZE_SP,
                                                  metrics);
        }

        @Override
        public boolean onScale(@NonNull final ScaleGestureDetector detector) {
            @Px
            final float currentSize = textView.getTextSize();
            final float factor = detector.getScaleFactor();
            @Px
            final float newSize = Math.max(minSizePx, Math.min(currentSize * factor, maxSizePx));
            textView.setTextSize(TypedValue.COMPLEX_UNIT_PX, newSize);
            return true;
        }
    }

    public class ButtonAdapter
            extends RecyclerView.Adapter<Holder>
            implements ItemTouchHelperAdapter {

        @NonNull

        private final LayoutInflater inflater;

        ButtonAdapter(@NonNull final Context context) {
            inflater = LayoutInflater.from(context);
        }

        @NonNull
        @Override
        public Holder onCreateViewHolder(@NonNull final ViewGroup parent,
                                         final int viewType) {
            final RowButtonBinding rVb = RowButtonBinding.inflate(inflater, parent, false);
            return new Holder(rVb);
        }

        @Override
        public void onBindViewHolder(@NonNull final Holder holder,
                                     final int position) {
            final UserButton userButton = list.get(position);
            final String label = userButton.getLabel();
            if (label.isEmpty()) {
                holder.vb.action.setText(R.string.button_not_set);
            } else {
                holder.vb.action.setText(label);
            }

            holder.vb.action.setOnClickListener(v -> {
                if (userButton.isPersisted()) {
                    clearOutput();
                    //noinspection DataFlowIssue
                    vm.execute(getContext(), userButton);
                } else {
                    edit(userButton.getPosition());
                }
            });
            holder.vb.action.setOnLongClickListener(v -> {
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

            final MenuItem item = menu.findItem(R.id.MENU_WRAP_OUTPUT);
            setWrapIcon(item);
        }

        private void setWrapIcon(@NonNull final MenuItem item) {
            item.setIcon(isWrap() ? R.drawable.notes_24px : R.drawable.wrap_text_24px);
        }

        @Override
        public boolean onMenuItemSelected(@NonNull final MenuItem menuItem) {
            final int itemId = menuItem.getItemId();

            if (itemId == R.id.MENU_CLEAR) {
                clearOutput();
                return true;

            } else if (itemId == R.id.MENU_WRAP_OUTPUT) {
                toggleWrap();
                setWrapIcon(menuItem);
                selectOutputView();
                return true;

            } else if (itemId == R.id.MENU_GLOBAL_SETTINGS) {
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

            } else if (itemId == R.id.MENU_CREATE_DEBUG_REPORT) {
                final String fileName = "sshremote-debug-" + LocalDate
                        .now().format(DateTimeFormatter.ISO_LOCAL_DATE);
                final String mimeType = getMimeTypeFromExtension("zip");
                createDocumentLauncher.launch(new GetContentUriForWritingContract
                        .Input(mimeType, fileName));

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

                } catch (final PackageManager.NameNotFoundException e) {
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

        @NonNull
        String getMimeTypeFromExtension(@NonNull final String fileExt) {
            final String mimeType = MimeTypeMap.getSingleton().getMimeTypeFromExtension(fileExt);
            if (mimeType != null) {
                return mimeType;
            }
            // fallback
            return "application/" + fileExt;
        }
    }
}
