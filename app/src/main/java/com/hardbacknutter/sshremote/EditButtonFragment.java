package com.hardbacknutter.sshremote;

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
import androidx.appcompat.widget.Toolbar;
import androidx.core.view.MenuProvider;
import androidx.lifecycle.ViewModelProvider;

import com.google.android.material.snackbar.Snackbar;

import java.util.List;

import com.hardbacknutter.sshremote.databinding.FragmentEditButtonBinding;
import com.hardbacknutter.sshremote.db.Command;
import com.hardbacknutter.sshremote.db.Config;
import com.hardbacknutter.sshremote.db.Host;
import com.hardbacknutter.sshremote.widgets.ExtArrayAdapter;
import com.hardbacknutter.sshremote.widgets.ExtTextWatcher;

public class EditButtonFragment
        extends BaseFragment {

    static final String TAG = "EditButtonFragment";

    private FragmentEditButtonBinding vb;

    private EditButtonViewModel vm;
    private CommandAdapter commandAdapter;
    private HostAdapter hostAdapter;

    @Override
    public View onCreateView(@NonNull final LayoutInflater inflater,
                             @Nullable final ViewGroup container,
                             @Nullable final Bundle savedInstanceState) {
        vb = FragmentEditButtonBinding.inflate(inflater, container, false);
        return vb.getRoot();
    }

    @Override
    public void onViewCreated(@NonNull final View view,
                              @Nullable final Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        final Context context = view.getContext();

        //noinspection ConstantConditions
        vm = new ViewModelProvider(getActivity()).get(EditButtonViewModel.class);
        vm.init(context, getArguments());
        vm.onConfigLoaded().observe(getViewLifecycleOwner(), this::onConfigLoaded);

        final Toolbar toolbar = initToolbar(new ToolbarMenuProvider());
        toolbar.setSubtitle(R.string.lbl_edit_button);
    }

    private void onConfigLoaded(@NonNull final Config config) {
        vb.buttonLabel.setText(config.label);
        vb.buttonLabel.addTextChangedListener((ExtTextWatcher) s -> vm.setLabel(s.toString()));

        initHostViews(config);
        initCommandViews(config);
    }

    private void initHostViews(@NonNull final Config config) {
        final List<Host> hostList = vm.getHostList();
        //noinspection ConstantConditions
        hostAdapter = new HostAdapter(getContext(), hostList);
        vb.host.setAdapter(hostAdapter);
        final Host host = hostList
                .stream()
                .filter(h -> h.id == config.hostId)
                .findFirst()
                .orElse(new Host());
        vb.host.setText(host.label, false);

        //noinspection ConstantConditions
        vb.host.setOnItemClickListener((av, v, position, id) -> vm
                .setHost(hostAdapter.getItem(position).id));

        vb.btnHostNew.setOnClickListener(v -> editHost(0));
        vb.btnHostEdit.setOnClickListener(v -> editHost(vm.getHost()));
    }

    private void initCommandViews(@NonNull final Config config) {
        final List<Command> commandList = vm.getCommandList();
        //noinspection ConstantConditions
        commandAdapter = new CommandAdapter(getContext(), commandList);
        vb.command.setAdapter(commandAdapter);
        final Command command = commandList
                .stream()
                .filter(c -> c.id == config.commandId)
                .findFirst()
                .orElse(new Command());
        vb.command.setText(command.label, false);

        //noinspection ConstantConditions
        vb.command.setOnItemClickListener((av, v, position, id) -> vm
                .setCommand(commandAdapter.getItem(position).id));

        vb.btnCommandNew.setOnClickListener(v -> editCommand(0));
        vb.btnCommandEdit.setOnClickListener(v -> editCommand(vm.getCommand()));
    }

    private void editHost(final int id) {
        final Bundle args = new Bundle();
        args.putInt(EditHostViewModel.ARGS_ID, id);
        final EditHostFragment fragment = new EditHostFragment();
        fragment.setArguments(args);
        getParentFragmentManager()
                .beginTransaction()
                .setReorderingAllowed(true)
                .addToBackStack(EditHostFragment.TAG)
                .replace(R.id.main_fragment, fragment, EditHostFragment.TAG)
                .commit();
    }

    private void editCommand(final int id) {
        final Bundle args = new Bundle();
        args.putInt(EditCommandViewModel.ARGS_ID, id);
        final EditCommandFragment fragment = new EditCommandFragment();
        fragment.setArguments(args);
        getParentFragmentManager()
                .beginTransaction()
                .setReorderingAllowed(true)
                .addToBackStack(EditCommandFragment.TAG)
                .replace(R.id.main_fragment, fragment, EditCommandFragment.TAG)
                .commit();
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

    private class ToolbarMenuProvider
            implements MenuProvider {

        @Override
        public void onCreateMenu(@NonNull final Menu menu,
                                 @NonNull final MenuInflater menuInflater) {
            menuInflater.inflate(R.menu.menu_edit, menu);
        }

        @Override
        public boolean onMenuItemSelected(@NonNull final MenuItem menuItem) {
            final int itemId = menuItem.getItemId();

            if (itemId == R.id.MENU_SAVE) {
                if (vm.save()) {
                    getParentFragmentManager().popBackStack();
                } else {
                    Snackbar.make(vb.getRoot(), R.string.button_not_set, Snackbar.LENGTH_SHORT)
                            .show();
                }
                return true;

            } else if (itemId == R.id.MENU_DELETE) {
                vm.delete();
                getParentFragmentManager().popBackStack();
                return true;
            }
            return false;
        }
    }
}
