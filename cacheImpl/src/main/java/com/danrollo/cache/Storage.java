package com.danrollo.cache;

import java.io.Serializable;

/**
 * Read and Write an object to/from storage.
 * User: dan
 * Date: 8/15/12
 * Time: 11:29 PM
 */
public abstract class Storage {

    protected final String storeName;

    Storage(final String name) {
        storeName = name;
    }

    abstract void initStore(Serializable itemToStore);

    abstract void store(final Serializable itemToStore);
    abstract Object load();
}
