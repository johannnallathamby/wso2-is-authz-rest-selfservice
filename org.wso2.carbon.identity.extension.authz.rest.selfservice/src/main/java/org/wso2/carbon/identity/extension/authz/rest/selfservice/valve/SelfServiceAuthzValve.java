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

package org.wso2.carbon.identity.extension.authz.rest.selfservice.valve;

import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.auth.service.AuthenticationContext;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.extension.authz.rest.selfservice.internal.SelfServiceAuthzDataHolder;
import org.wso2.carbon.identity.extension.authz.rest.selfservice.wrapper.SelfServiceAuthzCatalinaRequestWrapper;
import org.wso2.carbon.user.api.AuthorizationManager;
import org.wso2.carbon.user.api.UserStoreException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

import static org.wso2.carbon.identity.extension.authz.rest.selfservice.Constants.*;

/**
 * Custom authorization valve to set the Request Wrapper to a thread local.
 */
public class SelfServiceAuthzValve extends ValveBase {

    private static final Log log = LogFactory.getLog(SelfServiceAuthzValve.class);

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {

        AuthenticationContext authenticationContext = (AuthenticationContext) request.getAttribute(AUTH_CONTEXT);
        String requestUri = request.getRequestURI();
        String method = request.getMethod();

        // Wrap only if it's a /scim2/Roles GET or PATCH request.
        // And if the authenticated user is not an already authorized user.
        if (StringUtils.contains(requestUri, SCIM2_ROLES) && (HTTP_GET.equalsIgnoreCase(method) || HTTP_PATCH
                .equalsIgnoreCase(method)) && !isUserAuthorized(authenticationContext, method)) {

            SelfServiceAuthzCatalinaRequestWrapper wrapper = new SelfServiceAuthzCatalinaRequestWrapper(request);
            setThreadLocalWrapper(wrapper);
            try {
                getNext().invoke(wrapper, response);
            } catch (Throwable e) {
                log.error("Error wrapping the request.", e);
            } finally {
                unsetThreadLocalWrapper();
                return;
            }
        }
        getNext().invoke(request, response);
    }

    private boolean isUserAuthorized(AuthenticationContext context, String method) throws ServletException{

        if (context != null && context.getUser() != null && org.apache.commons.lang.StringUtils
                .isNotEmpty(context.getUser().getUserName())) {
            String username = context.getUser().getUserName();
            try {
                AuthorizationManager authorizationManager = SelfServiceAuthzDataHolder.getInstance().getRealmService()
                        .getTenantUserRealm(getTenantId()).getAuthorizationManager();
                String permission = HTTP_GET.equalsIgnoreCase(method) ? ROLE_VIEW_PERMISSION : ROLE_UPDATE_PERMISSION;
                return authorizationManager.isUserAuthorized(username, permission, UI_EXECUTE);
            } catch (UserStoreException e) {
                log.error("Error authorizing the user for SCIM2 roles : " + method, e);
                throw new ServletException(e);
            }
        }
        return false;
    }

    private void setThreadLocalWrapper(HttpServletRequest wrapper) {

        IdentityUtil.threadLocalProperties.get().put(REQUEST_WRAPPER, wrapper);
    }

    private void unsetThreadLocalWrapper() {

        IdentityUtil.threadLocalProperties.get().remove(REQUEST_WRAPPER);
    }

    private int getTenantId() {

        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
    }
}
