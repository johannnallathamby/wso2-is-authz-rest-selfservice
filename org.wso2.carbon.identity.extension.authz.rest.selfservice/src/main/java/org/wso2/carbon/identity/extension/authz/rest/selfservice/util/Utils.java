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

package org.wso2.carbon.identity.extension.authz.rest.selfservice.util;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.extension.authz.rest.selfservice.Constants;
import org.wso2.carbon.identity.extension.authz.rest.selfservice.exception.SelfServiceAuthzClientException;
import org.wso2.carbon.identity.extension.authz.rest.selfservice.exception.SelfServiceAuthzException;
import org.wso2.carbon.identity.extension.authz.rest.selfservice.exception.SelfServiceAuthzServerException;
import org.wso2.carbon.identity.extension.authz.rest.selfservice.internal.SelfServiceAuthzDataHolder;
import org.wso2.carbon.identity.role.mgt.core.IdentityRoleManagementException;
import org.wso2.carbon.identity.role.mgt.core.Role;
import org.wso2.carbon.identity.role.mgt.core.RoleManagementService;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;

public class Utils {

    public static String getUserIDFromUserName(String username, int tenantId)
            throws SelfServiceAuthzException {

        if (username == null) {
            return null;
        }
        try {
            AbstractUserStoreManager userStoreManager = (AbstractUserStoreManager) SelfServiceAuthzDataHolder
                    .getInstance().getRealmService().getTenantUserRealm(tenantId).getUserStoreManager();
            return userStoreManager.getUserIDFromUserName(username);
        } catch (UserStoreException e) {
            throw Utils.handleServerException(Constants.ErrorMessages.USER_STORE_OPERATONS_ERROR,
                    "Error obtaining ID for the username : " + username + ", tenant id : " + tenantId, e);
        }
    }

    public static String getRoleFromId(String roleId, String tenantDomain)
            throws SelfServiceAuthzException {

        try {
            RoleManagementService roleMgtService = SelfServiceAuthzDataHolder.getInstance().getRoleManagementService();
            Role role = roleMgtService.getRole(roleId, tenantDomain);
            if (role != null) {
                return role.getName();
            }
        } catch (IdentityRoleManagementException e) {
            throw Utils.handleServerException(Constants.ErrorMessages.ROLE_MGT_SERVICE_ERROR,
                    "Error while extracting the role from ID : " + roleId + ", tenant : " + tenantDomain);
        }
        return null;
    }

    public static SelfServiceAuthzClientException handleClientException(Constants.ErrorMessages error, String data) {

        String description;
        if (StringUtils.isNotBlank(data)) {
            description = String.format(error.getDescription(), data);
        } else {
            description = error.getDescription();
        }
        return new SelfServiceAuthzClientException(error.getMessage(), description, error.getCode());
    }

    public static SelfServiceAuthzClientException handleClientException(Constants.ErrorMessages error, String data,
                                                                        Throwable e) {

        String description;
        if (StringUtils.isNotBlank(data)) {
            description = String.format(error.getDescription(), data);
        } else {
            description = error.getDescription();
        }
        return new SelfServiceAuthzClientException(error.getMessage(), description, error.getCode(), e);
    }

    public static SelfServiceAuthzServerException handleServerException(Constants.ErrorMessages error, String data,
                                                                        Throwable e) {

        String message;
        if (StringUtils.isNotBlank(data)) {
            message = String.format(error.getMessage(), data);
        } else {
            message = error.getMessage();
        }
        return new SelfServiceAuthzServerException(message, error.getCode(), e);
    }

    public static SelfServiceAuthzServerException handleServerException(Constants.ErrorMessages error, String data) {

        String message;
        if (StringUtils.isNotBlank(data)) {
            message = String.format(error.getMessage(), data);
        } else {
            message = error.getMessage();
        }
        return new SelfServiceAuthzServerException(message, error.getCode());
    }
}
