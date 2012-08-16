package com.danrollo.cache;

import java.io.*;

/**
 * Read/Write an object to system memory.
 * User: dan
 * Date: 8/15/12
 * Time: 11:28 PM
 * To change this template use File | Settings | File Templates.
 */
public class StorageToMemory extends Storage {

    StorageToMemory(final String name) {
        super(name);
    }

    @Override
    public void initStore(Serializable itemToStore) {
        // do not create store if it already exists
        if (System.getProperties().get(storeName) == null) {
            store(itemToStore);
        }
    }

    @Override
    void store(Serializable itemToStore) {
        final ByteArrayOutputStream bos = new ByteArrayOutputStream();

        try {
            final ObjectOutputStream oos = new ObjectOutputStream(bos);
            try {
                oos.writeObject(itemToStore);
            } finally {
                oos.close();
            }
        } catch (IOException e) {
            throw new RuntimeException("Could not save object to disk.", e);
        }

        System.getProperties().put(storeName, bos.toByteArray());
    }

    @Override
    Object load() {
        byte[] objectBytes = (byte[]) System.getProperties().get(storeName);
        final ByteArrayInputStream bis = new ByteArrayInputStream(objectBytes);

        try {
            final ObjectInputStream is = new ObjectInputStream(bis);
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
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


}
