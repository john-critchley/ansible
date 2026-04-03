package biz.critchley.weblogic.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import weblogic.security.service.ContextHandler;
import weblogic.security.spi.IdentityAssertionException;
import weblogic.security.spi.IdentityAsserterV2;

import javax.security.auth.callback.CallbackHandler;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Validates a Google-issued RS256 ID token and extracts the WebLogic principal.
 *
 * Validation steps:
 *   1. Strip "Bearer " prefix if present (WebLogic may or may not strip it).
 *   2. Verify RS256 signature against Google's JWKS endpoint (cached by RemoteJWKSet).
 *   3. Check standard claims: exp, iat, iss (must be accounts.google.com).
 *   4. Optionally check aud against configured ExpectedAudience.
 *   5. Require email claim; reject if email_verified is false.
 *   6. Return local username: strip @domain if StripEmailDomain is true.
 *
 * RemoteJWKSet handles key caching and rotation transparently: it re-fetches
 * when a kid is not found in the cache, which covers Google's key rotation schedule.
 */
final class GoogleJwtIdentityAsserter implements IdentityAsserterV2 {

    private static final Logger LOG = Logger.getLogger(GoogleJwtIdentityAsserter.class.getName());

    private final GoogleJwtAssertionProviderMBean mbean;

    // RemoteJWKSet is thread-safe and caches keys internally.
    // Recreated only if the configured JWKS URL changes (rare/never in practice).
    private volatile JWKSource<SecurityContext> jwkSource;
    private volatile String cachedJwksUrl;

    GoogleJwtIdentityAsserter(GoogleJwtAssertionProviderMBean mbean) {
        this.mbean = mbean;
    }

    @Override
    public CallbackHandler assertIdentity(String tokenType, Object token, ContextHandler context)
            throws IdentityAssertionException {
        String username = validateAndExtract(extractRawJwt(token));
        LOG.info("GoogleJwtIdentityAsserter: asserted identity '" + username + "'");
        return new GoogleJwtCallbackHandler(username);
    }

    private String extractRawJwt(Object token) throws IdentityAssertionException {
        String raw;
        if (token instanceof byte[]) {
            raw = new String((byte[]) token).trim();
        } else if (token instanceof String) {
            raw = ((String) token).trim();
        } else {
            throw new IdentityAssertionException(
                "Unexpected token object type: " + token.getClass().getName());
        }
        // WebLogic may pass the full header value ("Bearer <jwt>") or just the jwt.
        if (raw.startsWith("Bearer ")) {
            raw = raw.substring(7).trim();
        }
        if (raw.isEmpty()) {
            throw new IdentityAssertionException("Empty bearer token");
        }
        return raw;
    }

    private String validateAndExtract(String rawJwt) throws IdentityAssertionException {
        try {
            ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();

            processor.setJWSKeySelector(
                new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, getJwkSource())
            );

            // Require iss, iat, exp, sub; Nimbus enforces exp/nbf automatically.
            processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                null,
                new JWTClaimsSet.Builder().build(),
                new HashSet<>(Arrays.asList("iss", "iat", "exp", "sub")),
                null
            ));

            JWTClaimsSet claims = processor.process(rawJwt, null);

            // Issuer must be Google
            String iss = claims.getIssuer();
            if (!"accounts.google.com".equals(iss) && !"https://accounts.google.com".equals(iss)) {
                throw new IdentityAssertionException("Unexpected token issuer: " + iss);
            }

            // Audience check (skip if not configured)
            String expectedAud = mbean.getExpectedAudience();
            if (expectedAud != null && !expectedAud.isEmpty()) {
                if (claims.getAudience() == null || !claims.getAudience().contains(expectedAud)) {
                    throw new IdentityAssertionException("Token audience does not match configured value");
                }
            }

            // Email claim — required
            String email = (String) claims.getClaim("email");
            if (email == null || email.isEmpty()) {
                throw new IdentityAssertionException("JWT contains no email claim");
            }

            // Reject unverified email addresses
            Object verified = claims.getClaim("email_verified");
            if (Boolean.FALSE.equals(verified) || "false".equalsIgnoreCase(String.valueOf(verified))) {
                throw new IdentityAssertionException("Google account email is not verified: " + email);
            }

            // Map to WebLogic username
            if (mbean.getStripEmailDomain() && email.contains("@")) {
                return email.substring(0, email.indexOf('@'));
            }
            return email;

        } catch (IdentityAssertionException e) {
            throw e;
        } catch (Exception e) {
            LOG.log(Level.WARNING, "JWT validation failed", e);
            throw new IdentityAssertionException("JWT validation failed: " + e.getMessage());
        }
    }

    private JWKSource<SecurityContext> getJwkSource() throws Exception {
        String url = mbean.getJwksUrl();
        if (jwkSource == null || !url.equals(cachedJwksUrl)) {
            synchronized (this) {
                if (jwkSource == null || !url.equals(cachedJwksUrl)) {
                    LOG.info("GoogleJwtIdentityAsserter: (re)initialising JWKS source from " + url);
                    jwkSource = new RemoteJWKSet<>(new URL(url));
                    cachedJwksUrl = url;
                }
            }
        }
        return jwkSource;
    }
}
