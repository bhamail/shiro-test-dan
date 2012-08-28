package com.danrollo.cache;

import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.SimpleSession;
import org.apache.shiro.session.mgt.eis.CachingSessionDAO;

import java.io.Serializable;
import java.util.Hashtable;

/**
 * A simple impl of the SessionDAO interface to provide shared, external backing storage for session objects.
 * User: dan
 * Date: 8/16/12
 * Time: 11:41 AM
 */
public class MySessionDAO extends CachingSessionDAO {

    private Hashtable<Serializable, Session> map = new Hashtable<Serializable, Session>();

    private final Storage storage;

    public MySessionDAO(final Storage storage) {
        this.storage = storage;
        storage.initStore(map);
    }


    private synchronized void store() {
        storage.store(map);
    }

    private synchronized void load() {
        //noinspection unchecked
        map = (Hashtable<Serializable, Session>) storage.load();
    }


    /**
     * Subclass implementation hook to actually persist the {@code Session}'s state to the underlying EIS.
     *
     * @param session the session object whose state will be propagated to the EIS.
     */
    @Override
    protected void doUpdate(Session session) {
        load();
        map.put(session.getId(), session);
        store();
    }

    /**
     * Subclass implementation hook to permanently delete the given Session from the underlying EIS.
     *
     * @param session the session instance to permanently delete from the EIS.
     */
    @Override
    protected void doDelete(Session session) {
        load();
        map.remove(session.getId());
        store();
    }

    /**
     * Subclass hook to actually persist the given <tt>Session</tt> instance to the underlying EIS.
     *
     * @param session the Session instance to persist to the EIS.
     * @return the id of the session created in the EIS (i.e. this is almost always a primary key and should be the
     *         value returned from {@link org.apache.shiro.session.Session#getId() Session.getId()}.
     */
    @Override
    protected Serializable doCreate(Session session) {
        if (session.getId() != null) {
            throw new IllegalStateException("SessionID is non-null during create call.");
        }

        final Serializable sessionId = generateSessionId(session);

        if (session instanceof SimpleSession) {
            ((SimpleSession) session).setId(sessionId);
        } else {
            throw new IllegalArgumentException("Unexpected session class for session: " + session);
        }

        load();
        map.put(sessionId, session);
        store();
        return sessionId;
    }

    /**
     * Subclass implementation hook that retrieves the Session object from the underlying EIS or {@code null} if a
     * session with that ID could not be found.
     *
     * @param sessionId the id of the <tt>Session</tt> to retrieve.
     * @return the Session in the EIS identified by <tt>sessionId</tt> or {@code null} if a
     *         session with that ID could not be found.
     */
    @Override
    protected Session doReadSession(Serializable sessionId) {
        load();
        return map.get(sessionId);
    }
}