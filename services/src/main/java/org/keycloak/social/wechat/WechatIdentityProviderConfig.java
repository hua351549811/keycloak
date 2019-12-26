/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.social.wechat;

import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

/**
 * 
 * @author hyh
 *
 */
public class WechatIdentityProviderConfig extends OAuth2IdentityProviderConfig {

    /**
	 * 
	 */
	private static final long serialVersionUID = -3975683970757351965L;

	public WechatIdentityProviderConfig(IdentityProviderModel model) {
        super(model);
    }
	
	/**
	 * 企业ID
	 * @return
	 */
	public String getCorpid() {
        return getConfig().get("corpid");
    }

    public void setUserIp(String corpid) {
    	getConfig().put("corpid", corpid);
    }

}
