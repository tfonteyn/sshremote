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

import com.hardbacknutter.sshremote.databinding.FragmentEditCommandBinding;
import com.hardbacknutter.sshremote.db.Command;
import com.hardbacknutter.sshremote.widgets.ExtTextWatcher;

public class EditCommandFragment
        extends BaseFragment {

    static final String TAG = "EditCommandFragment";

    private FragmentEditCommandBinding vb;

    private EditCommandViewModel vm;

    @Nullable
    @Override
    public View onCreateView(@NonNull final LayoutInflater inflater,
                             @Nullable final ViewGroup container,
                             @Nullable final Bundle savedInstanceState) {
        vb = FragmentEditCommandBinding.inflate(inflater, container, false);
        return vb.getRoot();
    }

    @Override
    public void onViewCreated(@NonNull final View view,
                              @Nullable final Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        final Context context = view.getContext();

        vm = new ViewModelProvider(this).get(EditCommandViewModel.class);
        vm.init(context, getArguments());
        vm.onConfigLoaded().observe(getViewLifecycleOwner(), this::onConfigLoaded);

        final Toolbar toolbar = initToolbar(new ToolbarMenuProvider());
        toolbar.setSubtitle(R.string.lbl_edit_command);
    }

    private void onConfigLoaded(@NonNull final Command command) {
        vb.commandLabel.setText(command.label);
        vb.commandLabel.addTextChangedListener(
                (ExtTextWatcher) s -> vm.setLabel(s.toString().trim()));

        vb.commandLine.setText(command.cmd);
        vb.commandLine.addTextChangedListener(
                (ExtTextWatcher) s -> vm.setCommand(s.toString().trim()));

        vb.sudoPassword.setEnabled(!command.sudoPassword.isEmpty());
        vb.sudoPassword.setText(command.sudoPassword);
        vb.sudoPassword.addTextChangedListener(
                (ExtTextWatcher) s -> vm.setSudoPassword(s.toString().trim()));

        vb.cbxSudo.setChecked(command.isSudo);
        vb.cbxSudo.setOnCheckedChangeListener((v, isChecked) -> vm.setSudo(isChecked));

        vb.cbxSudoUseUserPassword.setChecked(command.sudoPassword.isEmpty());
        vb.cbxSudoUseUserPassword.setOnCheckedChangeListener((v, isChecked) -> {
            if (isChecked) {
                vm.setSudoPassword("");
                vb.sudoPassword.setText("");
            }
            vb.sudoPassword.setEnabled(!isChecked);
        });
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
                //noinspection DataFlowIssue
                vm.save(getActivity());
                getParentFragmentManager().popBackStack();
                return true;

            } else if (itemId == R.id.MENU_DELETE) {
                //noinspection DataFlowIssue
                vm.delete(getActivity());
                getParentFragmentManager().popBackStack();
                return true;
            }
            return false;
        }
    }
}
