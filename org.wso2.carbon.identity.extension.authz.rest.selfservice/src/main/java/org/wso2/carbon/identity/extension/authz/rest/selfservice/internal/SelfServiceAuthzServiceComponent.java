/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.extension.authz.rest.selfservice.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.wso2.carbon.identity.authz.service.handler.AuthorizationHandler;
import org.wso2.carbon.identity.extension.authz.rest.selfservice.handler.SelfServiceAuthzHandler;
import org.wso2.carbon.identity.role.mgt.core.RoleManagementService;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * Service component for self-service authorization OSGI bundle.
 */
@Component(name = "wso2is.authz.rest.selfservice.component",
           immediate = true)
public class SelfServiceAuthzServiceComponent {

    private static final Log log = LogFactory.getLog(SelfServiceAuthzServiceComponent.class);

    @Activate
    protected void activate(ComponentContext cxt) {

        try {
            SelfServiceAuthzHandler selfServiceAuthzHandler = new SelfServiceAuthzHandler();
            cxt.getBundleContext().registerService(AuthorizationHandler.class, selfServiceAuthzHandler, null);
            if (log.isDebugEnabled())
                log.debug("Self-service authorization bundle activated successfully.");
        } catch (Throwable e) {
            log.error("Error while activating self-service authorization bundle.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.debug("Self-service authorization bundle is deactivated.");
        }
    }

    @Reference(name = "user.realmservice.default",
               service = org.wso2.carbon.user.core.service.RealmService.class,
               cardinality = ReferenceCardinality.MANDATORY,
               policy = ReferencePolicy.DYNAMIC,
               unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        SelfServiceAuthzDataHolder.getInstance().setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {

        SelfServiceAuthzDataHolder.getInstance().setRealmService(null);
    }

    @Reference(name = "registry.service",
               service = RegistryService.class,
               cardinality = ReferenceCardinality.MANDATORY,
               policy = ReferencePolicy.DYNAMIC,
               unbind = "unsetRegistryService")
    protected void setRegistryService(RegistryService registryService) {

        SelfServiceAuthzDataHolder.getInstance().setRegistryService(registryService);
    }

    protected void unsetRegistryService(RegistryService registryService) {

        SelfServiceAuthzDataHolder.getInstance().setRegistryService(null);
    }

    @Reference(name = "role.mgt.core",
               service = RoleManagementService.class,
               cardinality = ReferenceCardinality.MANDATORY,
               policy = ReferencePolicy.DYNAMIC,
               unbind = "unsetRoleMgtService")
    protected void setRoleMgtService(RoleManagementService roleMgtService) {

        SelfServiceAuthzDataHolder.getInstance().setRoleManagementService(roleMgtService);
    }

    protected void unsetRoleMgtService(RoleManagementService roleMgtService) {

        SelfServiceAuthzDataHolder.getInstance().setRoleManagementService(null);
    }
}
