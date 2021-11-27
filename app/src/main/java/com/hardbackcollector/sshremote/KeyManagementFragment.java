package com.hardbackcollector.sshremote;

import android.content.Context;
import android.net.Uri;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;
import androidx.navigation.NavController;
import androidx.navigation.fragment.NavHostFragment;
import androidx.recyclerview.widget.DividerItemDecoration;
import androidx.recyclerview.widget.ItemTouchHelper;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.snackbar.Snackbar;
import com.hardbackcollector.sshremote.databinding.FragmentKeyManagementBinding;
import com.hardbackcollector.sshremote.databinding.RowSshKeyBinding;
import com.hardbackcollector.sshremote.ddsupport.ItemTouchHelperAdapter;
import com.hardbackcollector.sshremote.ddsupport.SimpleItemTouchHelperCallback;
import com.hardbackcollector.sshremote.ssh.SshHelper;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

public class KeyManagementFragment
        extends Fragment {

    private static final String MIME_TYPES = "*/*";

    private FragmentKeyManagementBinding mVb;
    private KeyManagementViewModel mVm;

    /**
     * The launcher for picking a Uri to write to.
     */
    private final ActivityResultLauncher<String> mCreateDocumentLauncher =
            registerForActivityResult(new ActivityResultContracts.CreateDocument(),
                    this::exportToUri);
    private NavController mNavController;
    private HostKeyAdapter mAdapter;
    /**
     * The launcher for picking a Uri to read from.
     */
    private final ActivityResultLauncher<String> mOpenUriLauncher =
            registerForActivityResult(new ActivityResultContracts.GetContent(), this::onOpenUri);
    private ItemTouchHelper mItemTouchHelper;

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
        mVb = FragmentKeyManagementBinding.inflate(inflater, container, false);
        return mVb.getRoot();
    }

    @Override
    public void onViewCreated(@NonNull final View view,
                              @Nullable final Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        final Context context = view.getContext();

        mNavController = NavHostFragment.findNavController(this);

        mVm = new ViewModelProvider(this).get(KeyManagementViewModel.class);
        mVm.init(context);

        mAdapter = new HostKeyAdapter(context);
        mVb.keyList.setAdapter(mAdapter);
        mVb.keyList.addItemDecoration(
                new DividerItemDecoration(context, DividerItemDecoration.HORIZONTAL));

        final SimpleItemTouchHelperCallback sitHelperCallback =
                new SimpleItemTouchHelperCallback(mAdapter);
        sitHelperCallback.setItemViewSwipeEnabled(true);
        mItemTouchHelper = new ItemTouchHelper(sitHelperCallback);
        mItemTouchHelper.attachToRecyclerView(mVb.keyList);
    }

    @Override
    public void onCreateOptionsMenu(@NonNull final Menu menu,
                                    @NonNull final MenuInflater inflater) {
        inflater.inflate(R.menu.menu_key_management, menu);
    }

    @Override
    public boolean onOptionsItemSelected(@NonNull final MenuItem item) {
        final int itemId = item.getItemId();

        if (itemId == R.id.MENU_SAVE) {
            try {
                //noinspection ConstantConditions
                mVm.save(getContext());
                mNavController.popBackStack();
            } catch (final IOException e) {
                Snackbar.make(mVb.getRoot(), R.string.error_save_failed, Snackbar.LENGTH_LONG)
                        .show();
            }
            return true;

        } else if (itemId == R.id.MENU_IMPORT) {
            mVm.setImportIsAppend(false);
            mOpenUriLauncher.launch(MIME_TYPES);
            return true;

        } else if (itemId == R.id.MENU_IMPORT_APPEND) {
            mVm.setImportIsAppend(true);
            mOpenUriLauncher.launch(MIME_TYPES);
            return true;

        } else if (itemId == R.id.MENU_EXPORT) {
            mCreateDocumentLauncher.launch(SshHelper.KNOWN_HOSTS);
        }
        return false;
    }

    private void onOpenUri(@Nullable final Uri uri) {
        if (uri != null) {
            try {
                //noinspection ConstantConditions
                mVm.startImport(getContext(), uri);
                mAdapter.notifyDataSetChanged();
            } catch (final IOException | NoSuchAlgorithmException e) {
                Snackbar.make(mVb.getRoot(), R.string.error_import_failed, Snackbar.LENGTH_LONG)
                        .show();
            }
        }
    }

    private void exportToUri(@Nullable final Uri uri) {
        if (uri != null) {
            try {
                //noinspection ConstantConditions
                mVm.startExport(getContext(), uri);
            } catch (final IOException e) {
                Snackbar.make(mVb.getRoot(), R.string.error_export_failed, Snackbar.LENGTH_LONG)
                        .show();
            }
        }
    }

    private static class Holder
            extends RecyclerView.ViewHolder {

        @NonNull
        private final RowSshKeyBinding mVb;

        Holder(@NonNull final View itemView) {
            super(itemView);
            mVb = RowSshKeyBinding.bind(itemView);
        }
    }

    public class HostKeyAdapter
            extends RecyclerView.Adapter<Holder>
            implements ItemTouchHelperAdapter {

        @NonNull
        private final LayoutInflater mLayoutInflater;

        HostKeyAdapter(@NonNull final Context context) {
            mLayoutInflater = LayoutInflater.from(context);
        }

        @NonNull
        @Override
        public Holder onCreateViewHolder(@NonNull final ViewGroup parent,
                                         final int viewType) {
            final View view = mLayoutInflater.inflate(R.layout.row_ssh_key, parent, false);
            return new Holder(view);
        }

        @Override
        public void onBindViewHolder(@NonNull final Holder holder,
                                     final int position) {
            final KeyManagementViewModel.HostLine line = mVm.getHostList().get(position);

            holder.mVb.host.setText(line.host);
            holder.mVb.type.setText(line.type);
            holder.mVb.fingerprint.setText(line.fingerprint);
        }

        @Override
        public int getItemCount() {
            return mVm.getHostList().size();
        }

        @Override
        public void onItemSwiped(final int position) {
            mVm.getHostList().remove(position);
            notifyItemRemoved(position);
        }
    }
}
