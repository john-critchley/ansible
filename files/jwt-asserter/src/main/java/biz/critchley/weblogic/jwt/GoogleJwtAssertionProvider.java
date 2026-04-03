package biz.critchley.weblogic.jwt;

import weblogic.management.security.ProviderMBean;
import weblogic.security.provider.PrincipalValidatorImpl;
import weblogic.security.spi.AuthenticationProviderV2;
import weblogic.security.spi.IdentityAsserterV2;
import weblogic.security.spi.PrincipalValidator;
import weblogic.security.spi.SecurityServices;

import javax.security.auth.login.AppConfigurationEntry;
import java.util.HashMap;
import java.util.logging.Logger;

/**
 * WebLogic AuthenticationProviderV2 that validates Google-issued RS256 ID tokens.
 *
 * Deployed to $WL_HOME/wlserver/server/lib/mbeantypes/ as a shaded JAR.
 * Registered in the realm via WLST (config_jwt_asserter.py).
 *
 * Token flow:
 *   HTTP request with "Authorization: Bearer <google-id-token>"
 *   -> WebLogic sees active token type "Bearer"
 *   -> calls assertIdentity() on GoogleJwtIdentityAsserter
 *   -> JWKS fetch + RS256 verify + email extraction
 *   -> returns CallbackHandler supplying the local username (email minus @domain)
 *   -> DefaultIdentityAsserterLoginModule resolves principal via LDAPAuth
 */
public final class GoogleJwtAssertionProvider implements AuthenticationProviderV2 {

    private static final Logger LOG = Logger.getLogger(GoogleJwtAssertionProvider.class.getName());

    private GoogleJwtAssertionProviderMBean mbean;
    private GoogleJwtIdentityAsserter asserter;

    @Override
    public void initialize(ProviderMBean mbean, SecurityServices services) {
        this.mbean = (GoogleJwtAssertionProviderMBean) mbean;
        this.asserter = new GoogleJwtIdentityAsserter(this.mbean);
        LOG.info("GoogleJwtAssertionProvider: initialized. JWKS=" + this.mbean.getJwksUrl()
                + " stripDomain=" + this.mbean.getStripEmailDomain());
    }

    @Override
    public String getDescription() {
        return mbean.getDescription();
    }

    @Override
    public void shutdown() {
        LOG.info("GoogleJwtAssertionProvider: shutdown");
    }

    @Override
    public IdentityAsserterV2 getIdentityAsserter() {
        return asserter;
    }

    /** No standalone login module — identity assertion only. */
    @Override
    public AppConfigurationEntry getLoginModuleConfiguration() {
        return null;
    }

    /**
     * Use WebLogic's built-in identity assertion login module.
     * It reads the username from the CallbackHandler and establishes
     * the security context so LDAPAuth can resolve group membership.
     */
    @Override
    public AppConfigurationEntry getAssertionModuleConfiguration() {
        return new AppConfigurationEntry(
            "weblogic.security.provider.identityassertion.DefaultIdentityAsserterLoginModuleImpl",
            AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
            new HashMap<>()
        );
    }

    @Override
    public PrincipalValidator getPrincipalValidator() {
        return new PrincipalValidatorImpl();
    }
}
