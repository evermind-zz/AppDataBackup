package com.github.evermindzz.appdatabackup;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.text.InputType;
import android.text.TextUtils;
import android.text.method.PasswordTransformationMethod;
import android.util.Log;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Toast;

import java.io.File;
import java.util.regex.Pattern;

public class DataBackupRestoreActivity extends Activity {
    private static final String TAG = "DataBackupRestoreActivity";
    private static final String EXTRA_BACKUP_ENCRYPTION_MODE = "backup_encryption_mode";
    private static final String EXTRA_BACKUP_FILTER_REGEX = "backup_filter_pattern";
    private static final String EXTRA_BACKUP_SHARE_AUTHORITY = "backup_share_authority";
    private static final String EXTRA_BACKUP_WORKING_DIR = "backup_working_dir";
    private static final String EXTRA_BACKUP_ERASE_BEFORE_RESTORE = "backup_erase_before_restore";
    private static final String EXTRA_BACKUP_RESTORE_PERMISSIONS = "backup_restore_permissions";
    private static final String EXTRA_BACKUP_RESTORE_TIMESTAMPS = "backup_restore_timestamps";
    private static final String EXTRA_BACKUP_CREATE_LOGFILE = "backup_create_logfile";
    private Pattern fileFilter;
    private BackupUtils.EncryptionMode encryptionMode;
    private String authority;
    private boolean eraseBeforeRestore;
    private boolean restoreTimestamps;
    private boolean restorePermissions;
    private boolean createLogFile;
    private File workingDir;

    /**
     * Launches the DataBackupRestoreActivity with specified backup and restore configuration.
     * <p>
     * This method creates an Intent with a Bundle containing the encryption mode, file filter pattern,
     * authority for sharing files via CustomFileProvider, and restore options (erase before restore,
     * restore permissions, and restore timestamps). The activity uses these parameters to configure
     * backup or restore operations, such as creating a tarball with specific files or sharing it with
     * other apps.
     *
     * @param context            The context used to start the activity, typically an Activity or
     *                           Application context.
     * @param encryptionMode     The encryption mode for the backup (e.g., NONE, AES_128, AES_256).
     *                           Must not be null.
     * @param filterPattern      A regex pattern to filter files for the backup (e.g.,
     *                           "databases/.*\\.db$" to include only .db files in the databases/
     *                           directory). May be null to include all files.
     * @param authority          The authority for the CustomFileProvider (e.g.,
     *                           "com.github.evermindzz.appdatabackup.fileprovider") used to generate
     *                           content URIs for sharing. Must not be null.
     * @param workingDir         A dir within the app data eg. /data/data/0/<applicationId>. It should
     *                           already exists. If null it defaults to `context.getCacheDir()
     * @param eraseBeforeRestore Whether to erase existing data before restoring (default: false).
     * @param restorePermissions Whether to restore file permissions during restore (default: true).
     * @param restoreTimestamps  Whether to restore file timestamps during restore (default: true).
     * @param createLogfile      Create a logFile that is stored within the backup (default: false).
     * @throws IllegalArgumentException if context, encryptionMode, or authority is null.
     * @see DataBackupRestoreActivity
     * @see CustomFileProvider
     * @see BackupUtils.EncryptionMode
     */
    public static void launchActivity(
            Context context,
            BackupUtils.EncryptionMode encryptionMode,
            String filterPattern,
            String authority,
            File workingDir,
            boolean eraseBeforeRestore,
            boolean restorePermissions,
            boolean restoreTimestamps,
            boolean createLogfile) {
        if (context == null) {
            throw new IllegalArgumentException("Context must not be null");
        }
        if (encryptionMode == null) {
            throw new IllegalArgumentException("EncryptionMode must not be null");
        }
        if (authority == null) {
            throw new IllegalArgumentException("Authority must not be null");
        }

        final Intent intent = new Intent(context, DataBackupRestoreActivity.class);
        Bundle extras = new Bundle();
        extras.putInt(EXTRA_BACKUP_ENCRYPTION_MODE, encryptionMode.ordinal());
        if (filterPattern != null) {
            extras.putString(EXTRA_BACKUP_FILTER_REGEX, filterPattern);
        }
        extras.putString(EXTRA_BACKUP_SHARE_AUTHORITY, authority);
        extras.putSerializable(EXTRA_BACKUP_WORKING_DIR, workingDir != null ? workingDir : context.getCacheDir());
        extras.putBoolean(EXTRA_BACKUP_ERASE_BEFORE_RESTORE, eraseBeforeRestore);
        extras.putBoolean(EXTRA_BACKUP_RESTORE_PERMISSIONS, restorePermissions);
        extras.putBoolean(EXTRA_BACKUP_RESTORE_TIMESTAMPS, restoreTimestamps);
        extras.putBoolean(EXTRA_BACKUP_CREATE_LOGFILE, createLogfile);
        intent.putExtras(extras);
        context.startActivity(intent);
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_data_backup_restore);

        configureActivity(getIntent().getExtras());

        // Backup button
        Button backupButton = findViewById(R.id.backup_button);
        backupButton.setOnClickListener(v -> showBackupConfirmationDialog());

        // Restore button
        Button restoreButton = findViewById(R.id.restore_button);
        restoreButton.setOnClickListener(v -> {
            BackupUtils.startRestore(this);
        });
    }

    private void configureActivity(Bundle extras) {
        if (extras != null) {
            try {
                int modePos = extras.getInt(EXTRA_BACKUP_ENCRYPTION_MODE, BackupUtils.EncryptionMode.STRONG.ordinal());
                encryptionMode = BackupUtils.EncryptionMode.values()[modePos];

                String filterPattern = extras.getString(EXTRA_BACKUP_FILTER_REGEX, null);
                if (null != filterPattern) {
                    fileFilter = Pattern.compile(filterPattern);
                } else {
                    fileFilter = null;
                }

                authority = extras.getString(EXTRA_BACKUP_SHARE_AUTHORITY, getPackageName() + ".fileprovider");
                workingDir = (File) extras.getSerializable(EXTRA_BACKUP_WORKING_DIR);
                eraseBeforeRestore = extras.getBoolean(EXTRA_BACKUP_ERASE_BEFORE_RESTORE, false);
                restorePermissions = extras.getBoolean(EXTRA_BACKUP_RESTORE_PERMISSIONS, true);
                restoreTimestamps = extras.getBoolean(EXTRA_BACKUP_RESTORE_TIMESTAMPS, true);
                createLogFile = extras.getBoolean(EXTRA_BACKUP_CREATE_LOGFILE, false);
            } catch (IllegalArgumentException e) {
                Toast.makeText(this, "Invalid backup mode: " + e.getMessage(), Toast.LENGTH_LONG).show();
                throw e;
            }
        } else {
            throw new IllegalArgumentException("no Bundle extra data. Can't launch " + DataBackupRestoreActivity.class.getSimpleName());
        }
    }

    private void showBackupConfirmationDialog() {
        // Create dialog with password inputs
        LinearLayout layout = createPasswordInputLayout();

        EditText passwordInput = layout.findViewById(R.id.password_input);
        EditText confirmPasswordInput = layout.findViewById(R.id.confirm_password_input);

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("Confirm Backup")
                .setMessage("Create a backup of your app data? You can optionally set a password for encryption.")
                .setView(layout)
                .setPositiveButton("Backup", null) // Set listener later to prevent auto-dismiss
                .setNegativeButton("Cancel", (d, which) -> d.dismiss())
                .create();

        dialog.show();

        // Override positive button to validate passwords
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
            String password = passwordInput.getText().toString();
            String confirmPassword = confirmPasswordInput.getText().toString();

            // Validate passwords
            if (TextUtils.isEmpty(password) && TextUtils.isEmpty(confirmPassword)) {
                // No password provided, proceed with no encryption
                performBackup(null);
                dialog.dismiss();
            } else if (password.equals(confirmPassword)) {
                // Passwords match, proceed with encryption
                performBackup(password);
                dialog.dismiss();
            } else {
                // Passwords don't match
                Toast.makeText(this, "Passwords do not match", Toast.LENGTH_LONG).show();
            }
        });
    }

    private void showRestoreConfirmationDialog(android.net.Uri tarballUri) {
        // Create dialog with single password input
        LinearLayout layout = createPasswordInputLayout(false);

        EditText passwordInput = layout.findViewById(R.id.password_input);

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("Confirm Restore")
                .setMessage("Are you sure you want to restore this backup? Existing data will be erased.")
                .setView(layout)
                .setPositiveButton("Restore", (d, which) -> {
                    String password = passwordInput.getText().toString();
                    performRestore(tarballUri, TextUtils.isEmpty(password) ? null : password);
                })
                .setNegativeButton("Cancel", (d, which) -> d.dismiss())
                .create();

        dialog.show();
    }

    private LinearLayout createPasswordInputLayout() {
        return createPasswordInputLayout(true);
    }

    private LinearLayout createPasswordInputLayout(boolean includeConfirmPassword) {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        layout.setPadding(16, 16, 16, 16);

        // Show password checkbox
        CheckBox showPasswordCheckBox = new CheckBox(this);
        showPasswordCheckBox.setText("Show password");
        LinearLayout.LayoutParams checkBoxParams = new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
        );
        checkBoxParams.gravity = android.view.Gravity.END;
        showPasswordCheckBox.setLayoutParams(checkBoxParams);

        // Password input
        EditText passwordInput = new EditText(this);
        passwordInput.setId(R.id.password_input);
        passwordInput.setHint("Enter password (optional)");
        passwordInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        passwordInput.setTransformationMethod(PasswordTransformationMethod.getInstance());

        // Add views in order: checkbox, then password input
        layout.addView(showPasswordCheckBox);
        layout.addView(passwordInput);

        // Configure checkbox listener after adding password input
        showPasswordCheckBox.setOnCheckedChangeListener((buttonView, isChecked) -> {
            if (isChecked) {
                passwordInput.setTransformationMethod(null);
            } else {
                passwordInput.setTransformationMethod(PasswordTransformationMethod.getInstance());
            }
            // Move cursor to end to prevent visual glitches
            passwordInput.setSelection(passwordInput.getText().length());
        });

        if (includeConfirmPassword) {
            // Password confirmation
            EditText confirmPasswordInput = new EditText(this);
            confirmPasswordInput.setId(R.id.confirm_password_input);
            confirmPasswordInput.setHint("Confirm password");
            confirmPasswordInput.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
            confirmPasswordInput.setTransformationMethod(PasswordTransformationMethod.getInstance());
            layout.addView(confirmPasswordInput);

            // Update checkbox listener to handle both fields
            showPasswordCheckBox.setOnCheckedChangeListener((buttonView, isChecked) -> {
                if (isChecked) {
                    passwordInput.setTransformationMethod(null);
                    confirmPasswordInput.setTransformationMethod(null);
                } else {
                    passwordInput.setTransformationMethod(PasswordTransformationMethod.getInstance());
                    confirmPasswordInput.setTransformationMethod(PasswordTransformationMethod.getInstance());
                }
                passwordInput.setSelection(passwordInput.getText().length());
                confirmPasswordInput.setSelection(confirmPasswordInput.getText().length());
            });
        }

        return layout;
    }

    private void performBackup(String password) {
        BackupUtils.EncryptionMode encMode = password == null ? BackupUtils.EncryptionMode.NONE : encryptionMode;
        BackupUtilsAsync.createTarballAsync(this, password, encMode, fileFilter, createLogFile,
                workingDir, new BackupUtilsAsync.BackupCallback() {
            @Override
            public void onBackupComplete(File tarballFile, Exception error) {
                if (error != null) {
                    Toast.makeText(DataBackupRestoreActivity.this, "Backup failed: " + error.getMessage(), Toast.LENGTH_LONG).show();
                    Log.e(TAG, error.getMessage(), error);
                    return;
                }
                BackupUtils.shareTarball(DataBackupRestoreActivity.this, authority, tarballFile);
            }

            @Override
            public void onRestoreComplete(Exception error) {}
        });
    }

    private void performRestore(android.net.Uri tarballUri, String password) {
        BackupUtils.EncryptionMode encMode = password == null ? BackupUtils.EncryptionMode.NONE : encryptionMode;
        BackupUtilsAsync.restoreTarballAsync(this, tarballUri, password, encMode, eraseBeforeRestore, restorePermissions, restoreTimestamps,
                workingDir, new BackupUtilsAsync.BackupCallback() {
            @Override
            public void onBackupComplete(File tarballFile, Exception error) {}

            @Override
            public void onRestoreComplete(Exception error) {
                if (error != null) {
                    Toast.makeText(DataBackupRestoreActivity.this, "Restore failed: " + error.getMessage(), Toast.LENGTH_LONG).show();
                    Log.e(TAG, error.getMessage(), error);
                } else {
                    Toast.makeText(DataBackupRestoreActivity.this, "Restore successful", Toast.LENGTH_LONG).show();
                }
            }
        });
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == BackupUtils.REQUEST_CODE_RESTORE_BACKUP && resultCode == RESULT_OK && data != null) {
            showRestoreConfirmationDialog(data.getData());
        } else if (requestCode == BackupUtils.REQUEST_CODE_SHARE_BACKUP) {
            String tarballPath = BackupUtils.getSharedBackupPref(this)
                    .getString(BackupUtils.BACKUP_UTILS_LAST_TARBALL_PREF_KEY, null);
            if (tarballPath != null) {
                File tarballFile = new File(tarballPath);
                if (tarballFile.exists()) {
                    tarballFile.delete();
                }
                BackupUtils.getSharedBackupPref(this)
                        .edit()
                        .remove(BackupUtils.BACKUP_UTILS_LAST_TARBALL_PREF_KEY)
                        .apply();
            }
        }
    }
}