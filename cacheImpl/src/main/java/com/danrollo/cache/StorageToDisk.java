package com.danrollo.cache;

import java.io.*;

/**
 * Read/Write an object to disk.
 * User: dan
 * Date: 8/15/12
 * Time: 7:57 PM
 */
class StorageToDisk extends Storage {

    private final File diskFile;

    StorageToDisk(final String name) {
        super(name);
        diskFile = new File(System.getProperty("java.io.tmpdir"), name);
    }

    @Override
    public void initStore(Serializable itemToStore) {
        // do not create file if it already exists
        if (!diskFile.exists()) {
            store(itemToStore);
        }
    }

    @Override
    synchronized void store(final Serializable objectToStore) {
        try {

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
            throw new RuntimeException("Could not save object to disk.", e);
        }
    }

    @Override
    synchronized Object load() {
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
