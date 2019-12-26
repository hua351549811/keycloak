
package org.keycloak.social.okta;

import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.models.KeycloakSession;

/**
 * 
 * @author hyh
 *
 */
public class OktaIdentityProvider extends OIDCIdentityProvider  implements SocialIdentityProvider<OIDCIdentityProviderConfig> {
	public static final String AUTH_URL = "https://shijigroupchayhuang.okta.com/oauth2/v1/authorize";
	public static final String TOKEN_URL = "https://shijigroupchayhuang.okta.com/oauth2/v1/token";
	public static final String USER_URL = "https://shijigroupchayhuang.okta.com/oauth2/v1/userinfo";
	public OktaIdentityProvider(KeycloakSession session,
			OIDCIdentityProviderConfig config) {
		super(session, config);
		config.setAuthorizationUrl(AUTH_URL);
		config.setTokenUrl(TOKEN_URL);
		config.setUserInfoUrl(USER_URL);
	}







}
