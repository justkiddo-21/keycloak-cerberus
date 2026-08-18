package dev.kreslab.keycloak;

import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.models.KeycloakSession;

public class FreeIpaKerberosPasswordAuthenticatorFactory extends UsernamePasswordFormFactory {

    public static final String PROVIDER_ID = "freeipa-kerberos-password-form";

    private static final FreeIpaKerberosPasswordAuthenticator SINGLETON = new FreeIpaKerberosPasswordAuthenticator();

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "FreeIPA Kerberos Password Form";
    }

    @Override
    public String getHelpText() {
        return "Username/password form that validates credentials via a direct Kerberos AS-REQ "
                + "against the FreeIPA KDC, so an expired password correctly triggers the "
                + "Update Password required action instead of a generic invalid-credentials error.";
    }

    @Override
    public Authenticator create(KeycloakSession session) {
        return SINGLETON;
    }
}
