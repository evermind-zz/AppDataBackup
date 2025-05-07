package com.github.evermindzz.appdatabackup;

import android.content.ContentProvider;
import android.content.ContentProviderClient;
import android.content.ContentValues;
import android.content.Context;
import android.content.pm.ProviderInfo;
import android.content.res.XmlResourceParser;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import android.webkit.MimeTypeMap;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * A custom ContentProvider that mimics androidx.core.content.FileProvider, allowing secure file sharing
 * via content:// URIs. It maps directories defined in an XML resource to URI paths, supporting
 * arbitrary name attributes for flexible URI construction.
 * <p>
 * The whole purpose of this class is to avoid to have a dependency to
 * androidx.core:core or com.android.support:support-v4
 */
public class CustomFileProvider extends ContentProvider {
    // Columns returned by the query method for file metadata
    private static final String[] COLUMNS = {
            OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE
    };

    // Constants for XML parsing
    private static final String META_DATA_FILE_PROVIDER_PATHS = "android.support.FILE_PROVIDER_PATHS";
    private static final String TAG_ROOT_PATH = "root-path";
    private static final String TAG_FILES_PATH = "files-path";
    private static final String TAG_CACHE_PATH = "cache-path";
    private static final String TAG_EXTERNAL = "external-path";
    private static final String ATTR_NAME = "name";
    private static final String ATTR_PATH = "path";

    // Maps XML name attributes to PathStrategy objects for resolving files
    private final Map<String, PathStrategy> strategies = new HashMap<>();

    /**
     * Extracts the file extension from a filename.
     *
     * @param fileName The name of the file
     * @return The lowercase extension, or empty string if none
     */
    private static String getFileExtension(String fileName) {
        int dotIndex = fileName.lastIndexOf('.');
        return dotIndex >= 0 ? fileName.substring(dotIndex + 1).toLowerCase() : "";
    }

    /**
     * Generates a content URI for a given file, using the name attribute from the XML configuration.
     *
     * @param context   The application context
     * @param authority The provider's authority
     * @param file      The file to generate a URI for
     * @return A content URI (e.g., content://authority/name/subpath)
     * @throws IllegalArgumentException if the file is not in a configured directory
     */
    public static Uri getUriForFile(Context context, String authority, File file) {
        // Acquire the provider instance to access its strategies
        try (ContentProviderClient client = context.getContentResolver().acquireContentProviderClient(authority)) {
            if (client == null) {
                throw new IllegalStateException("Failed to acquire ContentProviderClient for authority: " + authority);
            }
            CustomFileProvider provider = (CustomFileProvider) client.getLocalContentProvider();
            if (provider == null) {
                throw new IllegalStateException("Provider not found for authority: " + authority);
            }

            // Find the strategy that matches the file's path
            String name = null;
            String relativePath = null;
            for (Map.Entry<String, PathStrategy> entry : provider.strategies.entrySet()) {
                String strategyName = entry.getKey();
                SimplePathStrategy strategy = (SimplePathStrategy) entry.getValue();
                File strategyDir = new File(strategy.baseDir, strategy.path);
                try {
                    String canonicalStrategyPath = strategyDir.getCanonicalPath();
                    String canonicalFilePath = file.getCanonicalPath();
                    if (canonicalFilePath.startsWith(canonicalStrategyPath)) {
                        name = strategyName;
                        // Extract the relative path after the strategy's directory
                        relativePath = canonicalFilePath.equals(canonicalStrategyPath) ? "" :
                                canonicalFilePath.substring(canonicalStrategyPath.length() + 1);
                        break;
                    }
                } catch (IOException e) {
                    android.util.Log.w("CustomFileProvider", "Failed to resolve canonical path for " + file.getAbsolutePath(), e);
                }
            }

            if (name == null) {
                throw new IllegalArgumentException("File not in known root: " + file.getAbsolutePath());
            }

            // Build the URI using the strategy's name
            Uri uri = new Uri.Builder()
                    .scheme("content")
                    .authority(authority)
                    .encodedPath("/" + name + (relativePath.isEmpty() ? "" : "/" + relativePath))
                    .build();
            android.util.Log.d("CustomFileProvider", "Generated URI: " + uri + " for file: " + file.getAbsolutePath());
            return uri;
        }
    }

    @Override
    public boolean onCreate() {
        // Initialize the provider; actual setup occurs in attachInfo
        return true;
    }

    @Override
    public void attachInfo(Context context, ProviderInfo info) {
        super.attachInfo(context, info);
        // Parse the XML configuration to initialize path strategies
        parseProviderInfo(context, info);
    }

    /**
     * Parses the XML resource specified in the provider's meta-data to create PathStrategy objects.
     * Each strategy maps a name attribute to a directory, used for URI-to-file resolution.
     *
     * @param context The application context
     * @param info    The provider's metadata from AndroidManifest.xml
     * @throws IllegalStateException if the XML is missing or parsing fails
     */
    private void parseProviderInfo(Context context, ProviderInfo info) {
        // Load the XML resource specified in meta-data
        XmlResourceParser parser = info.loadXmlMetaData(context.getPackageManager(), META_DATA_FILE_PROVIDER_PATHS);
        if (parser == null) {
            throw new IllegalStateException("Missing meta-data for CustomFileProvider.");
        }

        try {
            int type;
            // Iterate through XML tags
            while ((type = parser.next()) != XmlResourceParser.END_DOCUMENT) {
                if (type == XmlResourceParser.START_TAG) {
                    String tag = parser.getName();
                    String name = parser.getAttributeValue(null, ATTR_NAME);
                    String path = parser.getAttributeValue(null, ATTR_PATH);

                    // Determine the base directory based on the tag
                    File target = null;
                    if (TAG_ROOT_PATH.equals(tag)) {
                        target = new File("/");
                    } else if (TAG_FILES_PATH.equals(tag)) {
                        target = context.getFilesDir();
                    } else if (TAG_CACHE_PATH.equals(tag)) {
                        target = context.getCacheDir();
                    } else if (TAG_EXTERNAL.equals(tag)) {
                        target = context.getExternalFilesDir(null);
                    }

                    // Create and store a PathStrategy if all attributes are valid
                    if (target != null && name != null && path != null) {
                        strategies.put(name, new SimplePathStrategy(target, path));
                        android.util.Log.d("CustomFileProvider", "Added strategy: " + name + " for " + tag + " at " + target.getAbsolutePath() + "/" + path);
                    } else {
                        android.util.Log.w("CustomFileProvider", "Skipped invalid tag: " + tag + ", name=" + name + ", path=" + path);
                    }
                }
            }
            android.util.Log.d("CustomFileProvider", "Strategies loaded: " + strategies.keySet());
        } catch (Exception e) {
            throw new IllegalStateException("Failed to parse CustomFileProvider meta-data", e);
        } finally {
            parser.close();
        }
    }

    /**
     * Queries file metadata (display name and size) for a given URI.
     *
     * @param uri           The content URI
     * @param projection    Requested columns (defaults to DISPLAY_NAME and SIZE)
     * @param selection     Not used
     * @param selectionArgs Not used
     * @param sortOrder     Not used
     * @return A Cursor with the requested metadata
     */
    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        File file = getFileForUri(uri);
        if (projection == null) {
            projection = COLUMNS;
        }

        MatrixCursor cursor = new MatrixCursor(projection);
        Object[] row = new Object[projection.length];
        for (int i = 0; i < projection.length; i++) {
            if (OpenableColumns.DISPLAY_NAME.equals(projection[i])) {
                row[i] = file.getName();
            } else if (OpenableColumns.SIZE.equals(projection[i])) {
                row[i] = file.length();
            } else {
                row[i] = null;
            }
        }
        cursor.addRow(row);
        return cursor;
    }

    /**
     * Returns the MIME type of the file at the given URI.
     *
     * @param uri The content URI
     * @return The MIME type, or "application/octet-stream" if unknown
     */
    @Override
    public String getType(Uri uri) {
        File file = getFileForUri(uri);
        String extension = getFileExtension(file.getName());
        String mime = MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension);
        return mime != null ? mime : "application/octet-stream";
    }

    /**
     * Opens a file descriptor for the file at the given URI.
     *
     * @param uri  The content URI
     * @param mode The access mode ("r", "w", or "rw")
     * @return A ParcelFileDescriptor for the file
     * @throws FileNotFoundException if the file cannot be opened
     */
    @Override
    public ParcelFileDescriptor openFile(Uri uri, String mode) throws FileNotFoundException {
        File file = getFileForUri(uri);
        int fileMode = mode.contains("w") ? ParcelFileDescriptor.MODE_WRITE_ONLY :
                mode.contains("r") ? ParcelFileDescriptor.MODE_READ_ONLY :
                        ParcelFileDescriptor.MODE_READ_WRITE;
        try {
            return ParcelFileDescriptor.open(file, fileMode);
        } catch (IOException e) {
            throw new FileNotFoundException("Unable to open file: " + uri);
        }
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        throw new UnsupportedOperationException("Insert not supported");
    }

    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("Delete not supported");
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        throw new UnsupportedOperationException("Update not supported");
    }

    /**
     * Resolves a content URI to a File object.
     *
     * @param uri The content URI (e.g., content://authority/name/subpath)
     * @return The corresponding File
     * @throws IllegalArgumentException if the URI is invalid or the file doesn't exist
     */
    private File getFileForUri(Uri uri) {
        // Get the encoded path from the URI
        String path = uri.getEncodedPath();
        if (path == null) {
            throw new IllegalArgumentException("URI has no path: " + uri);
        }

        // Extract the name attribute (first path segment) and subpath
        int splitIndex = path.indexOf('/', 1);
        String tag = splitIndex > 0 ? path.substring(1, splitIndex) : path.substring(1);
        String subPath = splitIndex > 0 ? path.substring(splitIndex + 1) : "";

        // Look up the PathStrategy for the name attribute
        PathStrategy strategy = strategies.get(tag);
        if (strategy == null) {
            throw new IllegalArgumentException("No path strategy for: " + tag);
        }

        // Resolve the file using the strategy
        File file = strategy.getFileForPath(subPath);
        if (!file.exists()) {
            throw new IllegalArgumentException("File does not exist: " + file);
        }
        return file;
    }

    /**
     * Interface for resolving subpaths to files within a base directory.
     */
    private interface PathStrategy {
        File getFileForPath(String path);
    }

    /**
     * A simple implementation of PathStrategy that combines a base directory and XML path.
     */
    private static class SimplePathStrategy implements PathStrategy {
        private final File baseDir;
        private final String path;

        SimplePathStrategy(File baseDir, String path) {
            this.baseDir = baseDir;
            this.path = path;
        }

        @Override
        public File getFileForPath(String path) {
            File target = new File(baseDir, this.path);
            if (path.isEmpty()) {
                return target;
            }
            return new File(target, path);
        }
    }
}
