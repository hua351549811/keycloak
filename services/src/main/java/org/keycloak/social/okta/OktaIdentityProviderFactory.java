package org.keycloak.social.okta;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.broker.social.SocialIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

/**
 * @author hyh
 */
public class OktaIdentityProviderFactory extends AbstractIdentityProviderFactory<OktaIdentityProvider> implements SocialIdentityProviderFactory<OktaIdentityProvider> {

    public static final String PROVIDER_ID = "okta";

    @Override
    public String getName() {
        return "okta";
    }

    @Override
    public OktaIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new OktaIdentityProvider(session, new OIDCIdentityProviderConfig(model));
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
