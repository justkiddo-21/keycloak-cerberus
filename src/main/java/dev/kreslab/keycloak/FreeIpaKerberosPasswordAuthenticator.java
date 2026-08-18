package dev.kreslab.keycloak;

import jakarta.ws.rs.core.MultivaluedMap;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.models.UserModel;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.util.HashMap;
import java.util.Map;

/**
 * Standard UsernamePasswordForm, except password validation is done via a direct
 * Kerberos AS-REQ against the FreeIPA KDC instead of Keycloak's built-in LDAP/Kerberos
 * credential provider. Keycloak's own Kerberos-expiry detection pattern-matches error
 * strings written for Active Directory KDCs and does not recognize the message MIT
 * Kerberos/FreeIPA returns ("CLIENT KEY EXPIRED ... Password has expired"), so an
 * expired password there surfaces as a generic invalid_user_credentials error instead
 * of the UPDATE_PASSWORD required action. This authenticator does its own JAAS
 * Krb5LoginModule call and reads the exception chain directly.
 */
public class FreeIpaKerberosPasswordAuthenticator extends UsernamePasswordForm {

    private static final Logger log = Logger.getLogger(FreeIpaKerberosPasswordAuthenticator.class);

    private static final String KERBEROS_REALM = "KTV-LAB.LOCAL";

    @Override
    public boolean validatePassword(AuthenticationFlowContext context, UserModel user,
                                        MultivaluedMap<String, String> inputData, boolean clearUser) {
        String password = inputData.getFirst("password");
        if (user == null || password == null || password.isEmpty()) {
            return false;
        }

        String principal = user.getUsername() + "@" + KERBEROS_REALM;

        try {
            LoginContext lc = new LoginContext("freeipa-kerberos-expiry-check", null,
                    callbacks -> {
                        for (Callback cb : callbacks) {
                            if (cb instanceof NameCallback) {
                                ((NameCallback) cb).setName(principal);
                            } else if (cb instanceof PasswordCallback) {
                                ((PasswordCallback) cb).setPassword(password.toCharArray());
                            } else {
                                throw new UnsupportedCallbackException(cb);
                            }
                        }
                    },
                    krb5Config());
            lc.login();
            lc.logout();
            return true;
        } catch (LoginException e) {
            String chain = describeChain(e);
            log.debugf("Kerberos AS-REQ for %s failed: %s", principal, chain);
            if (chain.toLowerCase().contains("expired")) {
                log.infof("Password expired for %s (per FreeIPA KDC) - forcing UPDATE_PASSWORD", principal);
                user.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD.name());
                return true;
            }
            return false;
        } catch (Exception e) {
            log.errorf(e, "Unexpected error validating Kerberos credentials for %s", principal);
            return false;
        }
    }

    private static String describeChain(Throwable t) {
        StringBuilder sb = new StringBuilder();
        while (t != null) {
            if (t.getMessage() != null) {
                sb.append(t.getMessage()).append(" | ");
            }
            t = t.getCause();
        }
        return sb.toString();
    }

    private static Configuration krb5Config() {
        return new Configuration() {
            @Override
            public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
                Map<String, Object> options = new HashMap<>();
                options.put("tryFirstPass", "false");
                options.put("useFirstPass", "false");
                options.put("storeKey", "false");
                options.put("doNotPrompt", "false");
                options.put("debug", "false");
                return new AppConfigurationEntry[]{
                        new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
                                AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options)
                };
            }
        };
    }
}
