package com.hardbackcollector.sshremote;

import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;
import androidx.navigation.NavController;
import androidx.navigation.fragment.NavHostFragment;

import com.google.android.material.snackbar.Snackbar;
import com.hardbackcollector.sshremote.databinding.FragmentEditButtonBinding;
import com.hardbackcollector.sshremote.db.Command;
import com.hardbackcollector.sshremote.db.Config;
import com.hardbackcollector.sshremote.db.Host;
import com.hardbackcollector.sshremote.widgets.ExtArrayAdapter;
import com.hardbackcollector.sshremote.widgets.ExtTextWatcher;

import java.util.List;

public class EditConfigFragment
        extends Fragment {

    private NavController mNavController;

    private FragmentEditButtonBinding mVb;

    private EditConfigViewModel mVm;
    private CommandAdapter mCommandAdapter;
    private HostAdapter mHostAdapter;

    @Override
    public void onCreate(@Nullable final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setHasOptionsMenu(true);
    }

    @Override
    public View onCreateView(@NonNull final LayoutInflater inflater,
                             @Nullable final ViewGroup container,
                             @Nullable final Bundle savedInstanceState) {
        mVb = FragmentEditButtonBinding.inflate(inflater, container, false);
        return mVb.getRoot();
    }

    @Override
    public void onViewCreated(@NonNull final View view,
                              @Nullable final Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        final Context context = view.getContext();

        mNavController = NavHostFragment.findNavController(this);

        //noinspection ConstantConditions
        mVm = new ViewModelProvider(getActivity()).get(EditConfigViewModel.class);
        mVm.init(context, getArguments());
        mVm.onConfigLoaded().observe(getViewLifecycleOwner(), this::onConfigLoaded);
    }

    private void onConfigLoaded(@NonNull final Config config) {
        mVb.buttonLabel.setText(config.label);
        mVb.buttonLabel.addTextChangedListener((ExtTextWatcher) s -> mVm.setLabel(s.toString()));

        initHostViews(config);
        initCommandViews(config);
    }

    private void initHostViews(@NonNull final Config config) {
        final List<Host> hostList = mVm.getHostList();
        //noinspection ConstantConditions
        mHostAdapter = new HostAdapter(getContext(), hostList);
        mVb.host.setAdapter(mHostAdapter);
        final Host host = hostList
                .stream()
                .filter(h -> h.id == config.hostId)
                .findFirst()
                .orElse(new Host());
        mVb.host.setText(host.label, false);

        //noinspection ConstantConditions
        mVb.host.setOnItemClickListener((av, v, position, id) -> mVm
                .setHost(mHostAdapter.getItem(position).id));

        mVb.btnHostNew.setOnClickListener(v -> editHost(0));
        mVb.btnHostEdit.setOnClickListener(v -> editHost(mVm.getHost()));
    }

    private void initCommandViews(@NonNull final Config config) {
        final List<Command> commandList = mVm.getCommandList();
        //noinspection ConstantConditions
        mCommandAdapter = new CommandAdapter(getContext(), commandList);
        mVb.command.setAdapter(mCommandAdapter);
        final Command command = commandList
                .stream()
                .filter(c -> c.id == config.commandId)
                .findFirst()
                .orElse(new Command());
        mVb.command.setText(command.label, false);

        //noinspection ConstantConditions
        mVb.command.setOnItemClickListener((av, v, position, id) -> mVm
                .setCommand(mCommandAdapter.getItem(position).id));

        mVb.btnCommandNew.setOnClickListener(v -> editCommand(0));
        mVb.btnCommandEdit.setOnClickListener(v -> editCommand(mVm.getCommand()));
    }

    private void editHost(final int id) {
        final Bundle args = new Bundle();
        args.putInt(EditHostViewModel.ARGS_ID, id);
        mNavController.navigate(R.id.action_EditConfigFragment_to_editHostFragment, args);
    }

    private void editCommand(final int id) {
        final Bundle args = new Bundle();
        args.putInt(EditCommandViewModel.ARGS_ID, id);
        mNavController.navigate(R.id.action_editConfigFragment_to_editCommandFragment, args);
    }

    @Override
    public void onCreateOptionsMenu(@NonNull final Menu menu,
                                    @NonNull final MenuInflater inflater) {
        inflater.inflate(R.menu.menu_edit, menu);
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull final MenuItem item) {
        final int itemId = item.getItemId();

        if (itemId == R.id.MENU_SAVE) {
            if (mVm.save()) {
                mNavController.popBackStack();
            } else {
                Snackbar.make(mVb.getRoot(), R.string.button_not_set, Snackbar.LENGTH_SHORT)
                        .show();
            }
            return true;

        } else if (itemId == R.id.MENU_DELETE) {
            mVm.delete();
            mNavController.popBackStack();
            return true;
        }
        return false;
    }

    private static class HostAdapter
            extends ExtArrayAdapter<Host> {

        HostAdapter(@NonNull final Context context,
                    @NonNull final List<Host> list) {
            super(context, R.layout.dropdown_menu_popup_item, list);
        }

        @Override
        public long getItemId(final int position) {
            //noinspection ConstantConditions
            return getItem(position).id;
        }

        @NonNull
        @Override
        protected CharSequence getItemText(@Nullable final Host host) {
            return host == null ? "" : host.label;
        }
    }

    private static class CommandAdapter
            extends ExtArrayAdapter<Command> {

        CommandAdapter(@NonNull final Context context,
                       @NonNull final List<Command> list) {
            super(context, R.layout.dropdown_menu_popup_item, list);
        }

        @Override
        public long getItemId(final int position) {
            //noinspection ConstantConditions
            return getItem(position).id;
        }

        @NonNull
        @Override
        protected CharSequence getItemText(@Nullable final Command command) {
            return command == null ? "" : command.label;
        }
    }
}
