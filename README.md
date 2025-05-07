# BackupUtils for Android

## Overview
`BackupUtils` is a Java library for Android apps to back up and restore application data
in `/data/data/<package>/` without root access. It creates compressed, optionally
encrypted tarballs (`.tar` or `.tar.enc`) and supports sharing via `CustomFileProvider`.
Restoration extracts files to their original paths with configurable options. Compatible
with Android API 19 (4.4 KitKat) and above, it’s designed for reliability on older
devices and aims to be lightweight.

## Features
- **Backup Creation**: Generates tarballs from `/data/data/<package>/` (e.g.,
  `databases/`, `files/`) with nested `data.tar.gz`, stored in the cache directory.
- **Regex Filtering**: Filters files using regex patterns (e.g., `databases/.*\.db$`
  for database files).
- **Encryption**:
  - `NONE`: No encryption.
  - `WEAK`: Password as key (faster, less secure).
  - `STRONG`: PBKDF2-derived key with 10,000 iterations and 16-byte salt.
- **File Sharing**: Shares tarballs via `CustomFileProvider` using `ACTION_SEND`
  (e.g., email, cloud storage).
- **Restoration**:
  - Optionally erases existing data before restoring.
  - Restores Unix permissions using native APIs or `File.setReadable()`/`setWritable()`.
  - Preserves last-modified timestamps (`mtime`) with millisecond precision.
- **Database Handling**: Closes SQLite databases during restoration and verifies integrity.
- **User Interface**: Includes dialogs for backup/restore with password input, masking,
  and a "Show password" toggle.
- **Progress Feedback**: Displays a `ProgressDialog` with a progress bar.
- **Asynchronous Processing**: Uses `AsyncTask` for non-blocking operations.
- **Retention Policy**: Deletes old backups based on age or count.
- **Logging**: Stores optional gzipped logs in the tarball for debugging.

## Setup
### Prerequisites
1. Android project targeting API 19 (4.4) or higher.
2. Gradle build system.

### Dependencies
Add to `app/build.gradle`:
```gradle
dependencies {
    implementation 'com.github.evermind-zz:appdatabackup:1.0.0' // Replace with latest version
}
```

### Manifest Configuration
The library includes an `AndroidManifest.xml` that declares the `DataBackupRestoreActivity`
and a `CustomFileProvider` for sharing backup files.

The library provides the `backup_utils_file_paths.xml` meta-data file. You typically
don’t need a custom provider in your `AndroidManifest.xml` for this library.

If you need to add a custom provider, ensure the `android:authorities` attribute is unique
(e.g., replace `fileprovider` with `myprovider` or use `tools:replace="android:authorities"`).

The `backup_utils_file_paths.xml` can be overridden in your app with `tools:replace` directives.
```xml
<application>
    <provider
        android:name="com.github.evermindzz.appdatabackup.CustomFileProvider"
        tools:replace="android:authorities"
        android:authorities="${applicationId}.backupUtils.fileprovider"
        android:exported="false"
        android:grantUriPermissions="true">
        <meta-data
            android:name="android.support.FILE_PROVIDER_PATHS"
            tools:replace="android:resource"
            android:resource="@xml/backup_utils_file_paths" />
    </provider>
</application>
```

#### Recreate Resource Configuration
To use a custom `backup_utils_file_paths.xml` (or another filename) for
`CustomFileProvider`, ensure the path matches the temporary storage directory
specified in `DataBackupRestoreActivity.launchActivity()`. Below is the default
configuration included in the library:
```xml
<?xml version="1.0" encoding="utf-8"?>
<paths>
    <cache-path name="cache" path="." />
</paths>
```

## Integration
Launch `DataBackupRestoreActivity` to handle backup/restore with a prebuilt UI.
Example using a button:
```java
import android.content.Context;
import android.view.View;
import com.github.evermindzz.appdatabackup.BackupUtils;
import com.github.evermindzz.appdatabackup.DataBackupRestoreActivity;

public void setupLaunchBackupActivityButton(View view, Context context) {
    view.setOnClickListener(v -> DataBackupRestoreActivity.launchActivity(context,
            BackupUtils.EncryptionMode.STRONG,
            "databases/.*\\.db$",
            getPackageName() + ".backupUtils.fileprovider",
            context.getCacheDir(), // Directory for BackupUtils file creation
            false, // eraseBeforeRestore
            true,  // restorePermissions
            true,  // restoreTimestamps
            true   // createLogfile
    ));
}
```
See the Javadoc for `DataBackupRestoreActivity.launchActivity` for parameter details.

## Custom Integration
For a custom UI, use `BackupUtilsAsync` methods directly:
```java
import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.Toast;
import com.github.evermindzz.appdatabackup.BackupUtils;
import com.github.evermindzz.appdatabackup.BackupUtilsAsync;

public class CustomActivity extends Activity {
    private static final String AUTHORITY = "com.github.evermindzz.appdatabackup.backupUtils.fileprovider";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_custom);

        Button backupButton = findViewById(R.id.backup_button);
        backupButton.setOnClickListener(v -> {
            String password = "user_password"; // From EditText
            BackupUtilsAsync.createTarballAsync(this, password, BackupUtils.EncryptionMode.STRONG,
                    null, false, getCacheDir(), new BackupUtilsAsync.BackupCallback() {
                @Override
                public void onBackupComplete(File tarballFile, Exception error) {
                    if (error != null) {
                        Toast.makeText(CustomActivity.this, "Backup failed: " + error.getMessage(), Toast.LENGTH_LONG).show();
                        return;
                    }
                    BackupUtils.shareTarball(CustomActivity.this, AUTHORITY, tarballFile);
                }
                @Override
                public void onRestoreComplete(Exception error) {}
            });
        });

        Button restoreButton = findViewById(R.id.restore_button);
        restoreButton.setOnClickListener(v -> BackupUtils.startRestore(this));

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == BackupUtils.REQUEST_CODE_RESTORE_BACKUP && resultCode == RESULT_OK && data != null) {
            String password = "user_password"; // From EditText
            BackupUtilsAsync.restoreTarballAsync(this, data.getData(), password, BackupUtils.EncryptionMode.STRONG,
                    true, true, true, getCacheDir(), new BackupUtilsAsync.BackupCallback() {
                @Override
                public void onBackupComplete(File tarballFile, Exception error) {}
                @Override
                public void onRestoreComplete(Exception error) {
                    Toast.makeText(CustomActivity.this, error != null ? "Restore failed: " + error.getMessage() : "Restore successful", Toast.LENGTH_LONG).show();
                }
            });
        }
    }
}
```
You can also call `BackupUtils` directly.

## Configuration Options
- **Regex Filter** (`Pattern`): Filters files by relative path (e.g., `databases/.*\.db$`). Use `null` for all files.
- **Encryption Mode** (`EncryptionMode`): `NONE` (no encryption, `password=null`), `WEAK` (password as key), `STRONG` (PBKDF2-derived key).
- **Retention Policy** (`BackupRetentionPolicy`): Deletes old backups (e.g., keep last 2 or older than 7 days).
- **Erase Before Restore** (`boolean`): If `true`, clears `/data/data/<package>/` before restoring.
- **Restore Permissions** (`boolean`): If `true`, restores original permissions; otherwise, uses `0600` (files) or `0755` (dirs).
- **Restore Timestamps** (`boolean`): If `true`, restores `mtime`; otherwise, uses current time.

## Notes
- **Limitations**:
  - Permissions may combine group/others due to Android `File` API limitations, but 
    `libc` functions like `chmod` via the [OsExt](https://github.com/evermind-zz/OsExt/)
    `NativeUtils` library improve accuracy.
  - Only `mtime` is restored; `atime`/`ctime` require root access.
  - Non-SQLite databases may need custom closing logic.
- **Performance**: Strong encryption adds ~100-200 ms on API 19 devices.
- **Security**: Thoroughly test `eraseBeforeRestore` and `restorePermissions`, as they modify app data.
- **Compatibility**: Ensure `backup_utils_file_paths.xml` matches your app’s directory structure.
