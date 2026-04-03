package biz.critchley.weblogic.jwt;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.IOException;

/**
 * Supplies the asserted username to WebLogic's
 * DefaultIdentityAsserterLoginModuleImpl.
 *
 * NameCallback  — returns the username extracted from the JWT email claim.
 * PasswordCallback — returns an empty char array (no password in token auth).
 */
final class GoogleJwtCallbackHandler implements CallbackHandler {

    private final String username;

    GoogleJwtCallbackHandler(String username) {
        this.username = username;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback cb : callbacks) {
            if (cb instanceof NameCallback) {
                ((NameCallback) cb).setName(username);
            } else if (cb instanceof PasswordCallback) {
                ((PasswordCallback) cb).setPassword(new char[0]);
            } else {
                throw new UnsupportedCallbackException(cb,
                    "Unsupported callback: " + cb.getClass().getName());
            }
        }
    }
}
