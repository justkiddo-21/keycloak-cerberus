# Keycloak Cerberus

A Keycloak authenticator that catches expired FreeIPA/MIT Kerberos passwords
*before* the login flow completes, instead of letting them fail with a
generic "invalid credentials" error.

## The problem

Keycloak's built-in Kerberos credential provider recognizes password-expiry
errors by pattern-matching KDC error strings — but the patterns it knows are
written for Active Directory. MIT Kerberos / FreeIPA KDCs report expiry
differently (`CLIENT KEY EXPIRED ... Password has expired`), so Keycloak
never recognizes it. A user with a genuinely expired FreeIPA password just
gets bounced with `invalid_user_credentials`, with no indication *why*, and
no path to fix it without an admin's help.

## What this does

`Cerberus` replaces the standard username/password form authenticator with
one that performs its own Kerberos AS-REQ (via JAAS `Krb5LoginModule`)
directly against the KDC, and inspects the *actual* exception chain instead
of relying on Keycloak's AD-oriented string matching. When it detects an
expiry-related failure, it sets Keycloak's `UPDATE_PASSWORD` required action
on the user — which Keycloak enforces *before* completing the login/SSO
flow, so the user is sent straight to the password-reset screen instead of a
dead end.

## Requirements

- Keycloak 26.x with LDAP User Federation pointed at FreeIPA (or another MIT
  Kerberos KDC)
- The Keycloak host/container needs a working `/etc/krb5.conf` for the
  target realm
- Java 21

## Building

```
mvn clean package
```

Produces `target/freeipa-kerberos-expiry-authenticator-1.0.0.jar`.

## Installing

1. Drop the jar into `/opt/keycloak/providers/` and restart/rebuild Keycloak
   (`kc.sh build`).
2. Duplicate your realm's `browser` authentication flow (Admin Console ->
   Authentication -> browser flow -> "Duplicate").
3. In the duplicated flow, swap the `Username Password Form` execution for
   **FreeIPA Kerberos Password Form** (this provider, registered under id
   `freeipa-kerberos-password-form`).
4. Bind the duplicated flow as your realm's browser flow.

## Configuration

The Kerberos realm name is currently a constant,
`KERBEROS_REALM` in
[`FreeIpaKerberosPasswordAuthenticator.java`](src/main/java/dev/kreslab/keycloak/FreeIpaKerberosPasswordAuthenticator.java) —
edit it to match your own realm before building.

## License

MIT — see [LICENSE](LICENSE).
