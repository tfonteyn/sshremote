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

import com.hardbackcollector.sshremote.databinding.FragmentEditCommandBinding;
import com.hardbackcollector.sshremote.db.Command;
import com.hardbackcollector.sshremote.widgets.ExtTextWatcher;

public class EditCommandFragment
        extends Fragment {

    private FragmentEditCommandBinding mVb;

    private EditCommandViewModel mVm;

    private NavController mNavController;

    @Override
    public void onCreate(@Nullable final Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setHasOptionsMenu(true);
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull final LayoutInflater inflater,
                             @Nullable final ViewGroup container,
                             @Nullable final Bundle savedInstanceState) {
        mVb = FragmentEditCommandBinding.inflate(inflater, container, false);
        return mVb.getRoot();
    }

    @Override
    public void onViewCreated(@NonNull final View view,
                              @Nullable final Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        final Context context = view.getContext();

        mNavController = NavHostFragment.findNavController(this);

        mVm = new ViewModelProvider(this).get(EditCommandViewModel.class);
        mVm.init(context, getArguments());
        mVm.onConfigLoaded().observe(getViewLifecycleOwner(), this::onConfigLoaded);
    }

    private void onConfigLoaded(@NonNull final Command command) {
        mVb.commandLabel.setText(command.label);
        mVb.commandLabel.addTextChangedListener(
                (ExtTextWatcher) s -> mVm.setLabel(s.toString().trim()));

        mVb.commandLine.setText(command.cmd);
        mVb.commandLine.addTextChangedListener(
                (ExtTextWatcher) s -> mVm.setCommand(s.toString().trim()));

        mVb.sudoPassword.setEnabled(!command.sudoPassword.isEmpty());
        mVb.sudoPassword.setText(command.sudoPassword);
        mVb.sudoPassword.addTextChangedListener(
                (ExtTextWatcher) s -> mVm.setSudoPassword(s.toString().trim()));

        mVb.cbxSudo.setChecked(command.isSudo);
        mVb.cbxSudo.setOnCheckedChangeListener((v, isChecked) -> mVm.setSudo(isChecked));

        mVb.cbxSudoUseUserPassword.setChecked(command.sudoPassword.isEmpty());
        mVb.cbxSudoUseUserPassword.setOnCheckedChangeListener((v, isChecked) -> {
            if (isChecked) {
                mVm.setSudoPassword("");
                mVb.sudoPassword.setText("");
            }
            mVb.sudoPassword.setEnabled(!isChecked);
        });
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
            //noinspection ConstantConditions
            mVm.save(getActivity());
            mNavController.popBackStack();
            return true;

        } else if (itemId == R.id.MENU_DELETE) {
            //noinspection ConstantConditions
            mVm.delete(getActivity());
            mNavController.popBackStack();
            return true;
        }
        return false;
    }
}
