package com.danrollo.stuff;

import java.io.Serializable;

/**
 * A custom object that can be carried by a session.
 * User: dan
 * Date: 8/17/12
 * Time: 11:49 AM
 */
public class SomeSerializableObject implements Serializable {

    private static int counterStatic;

    private int counterInstance;

    private final String name;

    public SomeSerializableObject(final String name) {
        this.name = name;
    }

    public void increment() {
        counterStatic++;
        counterInstance++;
    }

    @Override
    public String toString() {
        return super.toString() + "->name: " + name
                + ", instance counter: " + counterInstance
                + ", static counter: " + counterStatic;
    }
}
