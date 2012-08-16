package com.danrollo.cache;

import java.io.*;

/**
 * Read/Write an object to disk.
 * User: dan
 * Date: 8/15/12
 * Time: 7:57 PM
 */
class DiskObject {

    static void store(final File diskFile, final Serializable objectToStore) {
        try {

            if (!diskFile.exists()) {
                if (!diskFile.createNewFile()) {
                    throw new IllegalStateException("Could not create cache file: " + diskFile.getCanonicalPath());
                }
            }

            final FileOutputStream fos = new FileOutputStream(diskFile);
            try {
                final ObjectOutputStream os = new ObjectOutputStream(fos);
                try {
                    os.writeObject(objectToStore);
                } finally {
                    os.close();
                }
            } finally {
                fos.close();
            }

        } catch (IOException e) {
            throw new IllegalStateException("Could not save object to disk.", e);
        }
    }

    static Object load(final File diskFile) {
        try {

            final FileInputStream fis = new FileInputStream(diskFile);
            try {
                final ObjectInputStream is = new ObjectInputStream(fis);
                try {
                    try {
                        //noinspection unchecked
                        return is.readObject();
                    } catch (ClassNotFoundException e) {
                        throw new RuntimeException(e);
                    }
                } finally {
                    is.close();
                }
            } finally {
                fis.close();
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
