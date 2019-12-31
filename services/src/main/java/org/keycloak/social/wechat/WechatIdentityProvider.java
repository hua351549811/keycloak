package org.keycloak.social.wechat;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

import javax.ws.rs.GET;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;

import org.keycloak.OAuth2Constants;
import org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider;
import org.keycloak.broker.oidc.mappers.AbstractJsonUserAttributeMapper;
import org.keycloak.broker.provider.AuthenticationRequest;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityBrokerException;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.broker.social.SocialIdentityProvider;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.events.EventType;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.ErrorPage;
import org.keycloak.services.messages.Messages;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * 
 * @author hyh
 *
 */
public class WechatIdentityProvider  extends AbstractOAuth2IdentityProvider<WechatIdentityProviderConfig> 
	implements SocialIdentityProvider<WechatIdentityProviderConfig>{
	
//	public static final String AUTHORIZE_URL = "https://open.weixin.qq.com/connect/qrconnect?appid=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s#wechat_redirect";
//	public static final String TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code";
//	public static final String USERINFO_URL = "https://api.weixin.qq.com/sns/userinfo?access_token=%s&openid=%s";
	
	public static final String AUTHORIZE_URL = "https://open.weixin.qq.com/connect/oauth2/authorize";
	public static final String TOKEN_URL = "https://api.weixin.qq.com/sns/oauth2/access_token";
	public static final String USERINFO_URL = "https://qyapi.weixin.qq.com/cgi-bin/user/getuserinfo";
	public static final String USER_URL = "https://qyapi.weixin.qq.com/cgi-bin/user/get?access_token=%s&userid=%s";
	public static final String ACCESSTOKEN_URL = "https://qyapi.weixin.qq.com/cgi-bin/gettoken?corpid=%s&corpsecret=%s";
	
	public static Set<String> codeSet = new HashSet<String>();

	
	public static final String DEFAULT_SCOPE = "snsapi_login";
	
	public WechatIdentityProvider(KeycloakSession session,
			WechatIdentityProviderConfig config) {
		super(session, config);
		config.setAuthorizationUrl(AUTHORIZE_URL);
		config.setTokenUrl(TOKEN_URL);
		config.setUserInfoUrl(USERINFO_URL);
		String defaultScope = config.getDefaultScope();

		if (defaultScope ==  null || defaultScope.trim().equals("")) {
			config.setDefaultScope(DEFAULT_SCOPE);
		}
	}
	private BrokeredIdentityContext extractUserInfo(JsonNode profile) {
//		BrokeredIdentityContext user = new BrokeredIdentityContext(getJsonProperty(profile, "openid"));
//
//		String username = getJsonProperty(profile, "openid");
//		user.setUsername(username);
//		user.setName(getJsonProperty(profile, "nickname"));
//		user.setIdpConfig(getConfig());
//		user.setIdp(this);
//
//		AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());
//
//		return user;
		
		BrokeredIdentityContext user = new BrokeredIdentityContext(getJsonProperty(profile, "userid"));

		String username = getJsonProperty(profile, "userid");
		user.setUsername(username);
		user.setName(getJsonProperty(profile, "alias"));
		user.setEmail(getJsonProperty(profile, "email"));
		user.setIdpConfig(getConfig());
		user.setIdp(this);

		AbstractJsonUserAttributeMapper.storeUserProfileForMapper(user, profile, getConfig().getAlias());

		return user;
	}
	
	@Override
	protected BrokeredIdentityContext doGetFederatedIdentity(String accessToken_code) {
		try {
//			logger.info("accessToken_code:"+accessToken_code);
//			JsonNode accessToken_codeJson = asJsonNode(accessToken_code);
//			String accessToken = getJsonProperty(accessToken_codeJson,  getAccessTokenResponseParameter());
//			String openid = getJsonProperty(accessToken_codeJson, "openid");
//			
//			String userIfoUrl = String.format(USERINFO_URL,accessToken,openid);
//			JsonNode userIfo = SimpleHttp.doGet(userIfoUrl, session).asJson();
//			logger.info("userIfo:"+userIfo);
//			return extractUserInfo(userIfo);
			
			logger.info("accessToken_code:"+accessToken_code);
			JsonNode accessToken_codeJson = asJsonNode(accessToken_code);
			String accessToken = getJsonProperty(accessToken_codeJson,  getAccessTokenResponseParameter());
			String code = getJsonProperty(accessToken_codeJson, "code");
			String url =USERINFO_URL+"?access_token=%s&code=%s";
			
			String userIfoUrl = String.format(url,accessToken,code);
			JsonNode userIfo = SimpleHttp.doGet(userIfoUrl, session).asJson();
			logger.info("userIfo:"+userIfo);
			String errcode = getJsonProperty(userIfo, "errcode");
			if("0".equals(errcode)){
				String userId = getJsonProperty(userIfo, "UserId");
				String userDetailUrl = String.format(USER_URL,accessToken,userId);
				JsonNode profile = SimpleHttp.doGet(userDetailUrl, session).asJson();
				logger.info("profile:"+profile);
				return extractUserInfo(profile);
			}
			return null;
		} catch (Exception e) {
			throw new IdentityBrokerException("Could not obtain user profile from github.", e);
		}
	}
	
	/**
	 * 根据token 获取身份信息
	 */
	public BrokeredIdentityContext getFederatedIdentity(String accessToken_code) {
	 	try {
			JsonNode accessToken_codeJson = asJsonNode(accessToken_code);
			
			String accessToken = getJsonProperty(accessToken_codeJson, getAccessTokenResponseParameter());
			String code = getJsonProperty(accessToken_codeJson, "code");
			
			if (accessToken == null) {
			    throw new IdentityBrokerException("No access token available in OAuth server response: " + accessToken);
			}
			String accessToken_code_str =  "{\""+ getAccessTokenResponseParameter()+"\":\""+accessToken+"\",\"code\":\""+code+"\"}";
			BrokeredIdentityContext context = doGetFederatedIdentity(accessToken_code_str);
			if(context==null){
				return null;
			}
			context.getContextData().put(FEDERATED_ACCESS_TOKEN, accessToken);
			return context;
		} catch (IOException e) {
			e.printStackTrace();
		}
	 	return null;
    }

	/**
	 * 构建Authorization url
	 */
	@Override
    protected UriBuilder createAuthorizationUrl(AuthenticationRequest request) {
        String url = getConfig().getAuthorizationUrl()+"?appid=%s&redirect_uri=%s&response_type=code&scope=%s&state=%s#wechat_redirect";
//        String url = String.format(getConfig().getAuthorizationUrl(), getConfig().getClientId(),request.getRedirectUri(),getConfig().getDefaultScope(),request.getState().getEncoded());
        url = String.format(url, getConfig().getCorpid(),request.getRedirectUri(),getConfig().getDefaultScope(),request.getState().getEncoded());
        UriBuilder uriBuilder = UriBuilder.fromUri(url);
        return uriBuilder;
        
    }
	/**
	 * sso 重定向回来，带code
	 */
	@Override
	public Object callback(RealmModel realm, AuthenticationCallback callback,EventBuilder event) {
		return new Endpoint(callback, realm, event){
			/**
			 * 获取微信的accesstoken
			 */
			@Override
			public SimpleHttp generateTokenRequest(String authorizationCode) {
				//"https://api.weixin.qq.com/sns/oauth2/access_token?appid=%s&secret=%s&code=%s&grant_type=authorization_code";
//				String url = String.format(TOKEN_URL, getConfig().getClientId(),getConfig().getClientSecret(),authorizationCode);
//	            return SimpleHttp.doGet(url, session);
	            
	            String url = String.format(ACCESSTOKEN_URL, getConfig().getCorpid(),getConfig().getClientSecret());
	            return SimpleHttp.doGet(url, session);
	        }
			
			 @Override
			 @GET
		        public Response authResponse(@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_STATE) String state,
		        		@QueryParam(AbstractOAuth2IdentityProvider.OAUTH2_PARAMETER_CODE) String authorizationCode,
		                                     @QueryParam(OAuth2Constants.ERROR) String error) {
	
		            try {
		            	if(codeSet.contains(authorizationCode)){
		            		return callback.cancelled(state);
		            	}
		            	codeSet.add(authorizationCode);
		            	
		            	logger.info("authorizationCode:"+authorizationCode);
		                if (authorizationCode != null) {
		                	SimpleHttp response_SimpleHttp = generateTokenRequest(authorizationCode);
		                	String response = response_SimpleHttp.asString();
		                	JsonNode accessToken_codeJson = asJsonNode(response);
		                	String accessToken = getJsonProperty(accessToken_codeJson, getAccessTokenResponseParameter());
//		                	String openid = getJsonProperty(accessToken_codeJson, "openid");
//		                	String accessToken_openid =  "{\""+getAccessTokenResponseParameter()+"\":\""+accessToken+"\",\"openid\":\""+openid+"\"}";
		                    String accessToken_openid =  "{\""+getAccessTokenResponseParameter()+"\":\""+accessToken+"\",\"code\":\""+authorizationCode+"\"}";
		                    logger.info("accessToken_code:"+accessToken_openid);
		                    BrokeredIdentityContext federatedIdentity = getFederatedIdentity(accessToken_openid);
		                    if(federatedIdentity==null){
		                    	return callback.cancelled(state);
		                    }
//		                    if (getConfig().isStoreToken()) {
//		                        // make sure that token wasn't already set by getFederatedIdentity();
//		                        // want to be able to allow provider to set the token itself.
//		                        if (federatedIdentity.getToken() == null)federatedIdentity.setToken(accessToken);
//		                    }
	
		                    federatedIdentity.setIdpConfig(getConfig());
		                    federatedIdentity.setIdp(WechatIdentityProvider.this);
		                    federatedIdentity.setCode(state);
	
		                    return callback.authenticated(federatedIdentity);
		                }
		            } catch (WebApplicationException e) {
		                return e.getResponse();
		            } catch (Exception e) {
		                logger.error("Failed to make identity provider oauth callback", e);
		            }
		            event.event(EventType.LOGIN);
		            event.error(Errors.IDENTITY_PROVIDER_LOGIN_FAILURE);
		            return ErrorPage.error(session, null, Response.Status.BAD_GATEWAY, Messages.IDENTITY_PROVIDER_UNEXPECTED_ERROR);
		        }
			
		};
	}
	
	@Override
	protected boolean supportsExternalExchange() {
		return true;
	}

	@Override
	protected String getProfileEndpointForValidation(EventBuilder event) {
		return USERINFO_URL;
	}
	
	@Override
	protected String getDefaultScopes() {
		return DEFAULT_SCOPE;
	}

	
	
}
