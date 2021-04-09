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

package org.wso2.carbon.identity.extension.authz.rest.selfservice.handler;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.authz.service.AuthorizationContext;
import org.wso2.carbon.identity.authz.service.AuthorizationResult;
import org.wso2.carbon.identity.authz.service.AuthorizationStatus;
import org.wso2.carbon.identity.authz.service.exception.AuthzServiceServerException;
import org.wso2.carbon.identity.authz.service.handler.AuthorizationHandler;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.extension.authz.rest.selfservice.exception.SelfServiceAuthzException;
import org.wso2.carbon.identity.extension.authz.rest.selfservice.internal.SelfServiceAuthzDataHolder;
import org.wso2.carbon.identity.extension.authz.rest.selfservice.util.Utils;
import org.wso2.carbon.identity.extension.authz.rest.selfservice.wrapper.SelfServiceAuthzCatalinaRequestWrapper;
import org.wso2.carbon.identity.extension.authz.rest.selfservice.wrapper.SelfServiceAuthzHTTPServletRequestWrapper;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.registry.core.Resource;
import org.wso2.carbon.registry.core.exceptions.RegistryException;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.wso2.carbon.identity.extension.authz.rest.selfservice.Constants.*;
import static org.wso2.carbon.identity.extension.authz.rest.selfservice.Constants.ErrorMessages.GET_MGT_ROLES_REGISTRY_ERROR;
import static org.wso2.carbon.identity.extension.authz.rest.selfservice.Constants.ErrorMessages.GET_MGT_ROLES_UNSUPPORTED_ENCODING_ERROR;
import static org.wso2.carbon.identity.extension.authz.rest.selfservice.util.Utils.getRoleFromId;
import static org.wso2.carbon.identity.extension.authz.rest.selfservice.util.Utils.getUserIDFromUserName;

/**
 * Custom authorization handler to by pass SCIM2 Roles GET and PATCH requests.
 */
public class SelfServiceAuthzHandler extends AuthorizationHandler {

    private static final Log log = LogFactory.getLog(SelfServiceAuthzHandler.class);

    @Override
    public AuthorizationResult handleAuthorization(AuthorizationContext authorizationContext)
            throws AuthzServiceServerException {

        // Authorize with default handler first.
        AuthorizationResult result = super.handleAuthorization(authorizationContext);
        if (result.getAuthorizationStatus().equals(AuthorizationStatus.GRANT)) {
            return result;
        }

        // If denied by the default handler, check if the request should be bypassed.
        // Check if the request wrapper is available in the thread local.
        if (IdentityUtil.threadLocalProperties.get() == null
                || IdentityUtil.threadLocalProperties.get().get(REQUEST_WRAPPER) == null) {
            return result;
        }
        SelfServiceAuthzHTTPServletRequestWrapper wrapper = (SelfServiceAuthzHTTPServletRequestWrapper)
                (((SelfServiceAuthzCatalinaRequestWrapper) IdentityUtil.threadLocalProperties.get()
                .get(REQUEST_WRAPPER)).getRequest());

        String requestUri = wrapper.getRequestURI();
        String method = wrapper.getMethod();
        String queryString = wrapper.getQueryString();

        // Check if /scim2/Roles PATCH/GET and intercept.
        boolean shouldIntercept =
                StringUtils.containsIgnoreCase(requestUri, SCIM2_ROLES) && (HTTP_GET.equalsIgnoreCase(method)
                        || HTTP_PATCH.equalsIgnoreCase(method));

        // Check if /scim2/Roles PATCH request.
        Map body;
        if (shouldIntercept && HTTP_PATCH.equals(method)) {
            boolean isPermissiblePatch = false;
            try {
                body = new ObjectMapper().readValue(wrapper.getBody(), HashMap.class);
                isPermissiblePatch = isSelfServiceAuthzRole(requestUri) && isSelfAssignRequest(body);
            } catch (JsonProcessingException | SelfServiceAuthzException e) {
                log.error("Error while parsing the request.", e);
            } catch (IOException e) {
                log.error("Error while reading the request body.", e);
            }
            if (isPermissiblePatch) {
                result.setAuthorizationStatus(AuthorizationStatus.GRANT);
            }
            return result;
        }

        // Check if /scim2/Roles GET request with 'filter=displayName+sw+APP_' filter.
        boolean isRoleFilterRequest;
        try {
            isRoleFilterRequest = StringUtils.isNotBlank(queryString) && isSelfServiceAuthzRoleFilteringRequest(queryString);
        } catch (SelfServiceAuthzException e) {
            log.error("Error while checking the request filter.", e);
            throw new AuthzServiceServerException(e);
        }
        if (shouldIntercept && HTTP_GET.equals(method) && isRoleFilterRequest) {
            result = new AuthorizationResult(AuthorizationStatus.GRANT);
        }
        return result;
    }

    @Override
    public String getName() {

        return "SelfServiceAuthzRestHandler";
    }

    @Override
    public int getPriority() {

        return 50;
    }

    /**
     * Check if the Role is going to be assigned to the authenticated user itself.
     * and if the request is a Role member adding/removing request.
     *
     * @param body
     * @return
     * @throws SelfServiceAuthzException
     */
    private boolean isSelfAssignRequest(Map body) throws SelfServiceAuthzException {

        if (body != null && body.get("Operations") != null && body.get("Operations") instanceof ArrayList
                && ((ArrayList)body.get("Operations")).get(0) != null
                && ((ArrayList)body.get("Operations")).get(0) instanceof Map) {
            Map operations = ((Map)((ArrayList)body.get("Operations")).get(0));
//            String path = operations.get("path") != null && operations.get("path") instanceof String
//                    ? (String) operations.get("path")
//                    : null;
//            // Check if user patch.
//            if (!PATCH_PATH_USERS.equalsIgnoreCase(path)) {
//                return false;
//            }
            Map membersList = operations.get("value") != null && operations.get("value") instanceof Map
                    ? (Map)operations.get("value"): new HashMap();

            ArrayList values = membersList.get("members") != null && membersList.get("members") instanceof ArrayList
                    ? (ArrayList) membersList.get("members")
                    : new ArrayList();
            String authenticateUserId = getAuthenticatedUserId();
            // Check if multiple user patch.
            if (values.size() != 1 || !(values.get(0) instanceof Map) || authenticateUserId == null) {
                return false;
            }
            String member = (String) ((LinkedHashMap) values.get(0)).get("value");
            if (log.isDebugEnabled()) {
                log.debug("SCIM patch member : " + member);
            }
            // Check if self assigning.
            return authenticateUserId.equals(StringUtils.trim(member));
        }
        return false;
    }

    /**
     * Check if the Role is a self-service auhtorization role with the given prefix.
     *
     * @param uri
     * @return
     */
    private boolean isSelfServiceAuthzRole(String uri) throws SelfServiceAuthzException {

        String[] segments = uri.split("/");
        String roleId = segments[segments.length - 1];
        String roleName = getRoleFromId(roleId, getTenantDomain());
        // 'APP_' is the default role prefix if not defined otherwise in the registry.
        String rolePrefix = readRolePrefixFromRegistry();
        rolePrefix = StringUtils.isNotBlank(rolePrefix) ? rolePrefix.trim() : StringUtils.trim(rolePrefix);
        // Check if role starts with the given prefix.
        if (StringUtils.isNotBlank(roleName)) {
            return StringUtils.startsWithIgnoreCase(roleName, rolePrefix);
        }
        return false;
    }

    private boolean isSelfServiceAuthzRoleFilteringRequest(String queryString) throws SelfServiceAuthzException {

        // Check if there's a query matching 'filter=displayName+sw+APP_'.
        Map<String, String> queryMap = splitQuery(queryString);
        String requestFilter = queryMap.get(FILTER_QUERY_PARAM_NAME);
        // 'APP_' is the default role prefix if not defined otherwise in the registry.
        String rolePrefix = readRolePrefixFromRegistry();
        rolePrefix = StringUtils.isNotBlank(rolePrefix) ? rolePrefix.trim() : StringUtils.trim(rolePrefix);

        String roleFilterValue = ROLE_FILTER_QUERY_STRING.replace("#", rolePrefix);
        if (log.isDebugEnabled()) {
            log.debug("Request's filter : " + requestFilter);
            log.debug("Filter value to bypass : " + roleFilterValue);
        }
        return roleFilterValue.equalsIgnoreCase(requestFilter);
    }

    public static Map<String, String> splitQuery(String queryString) throws SelfServiceAuthzException {

        Map<String, String> query_pairs = new LinkedHashMap<>();
        String[] pairs = queryString.split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            try {
                query_pairs.put(URLDecoder.decode(pair.substring(0, idx), "UTF-8"),
                        URLDecoder.decode(pair.substring(idx + 1), "UTF-8"));
            } catch (UnsupportedEncodingException e) {
                throw Utils.handleClientException(GET_MGT_ROLES_UNSUPPORTED_ENCODING_ERROR, null, e);
            }
        }
        return query_pairs;
    }

    private String readRolePrefixFromRegistry() throws SelfServiceAuthzException {

        String rolePrefix;
        try {
            Registry registry = getConfigRegistry(getTenantId());
            if (registry.resourceExists(MGT_ROLES_REGISTRY_RESOURCE)) {
                Resource resource = registry.get(MGT_ROLES_REGISTRY_RESOURCE);
                rolePrefix = resource.getProperty(MGT_ROLES_REGISTRY_PROPERTY);
            } else {
                rolePrefix = DEFAULT_ROLE_PREFIX;
            }
        } catch (RegistryException e) {
            throw Utils.handleServerException(GET_MGT_ROLES_REGISTRY_ERROR, e.getMessage(), e);
        }
        if (log.isDebugEnabled()) {
            log.debug(MGT_ROLES_REGISTRY_PROPERTY + " : " + rolePrefix);
        }
        return rolePrefix;
    }

    private Registry getConfigRegistry(int tenantId) throws RegistryException {

        return SelfServiceAuthzDataHolder.getInstance().getRegistryService().getConfigSystemRegistry(tenantId);
    }

    private String getTenantDomain() {

        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
    }

    private int getTenantId() {

        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
    }

    private String getAuthenticatedUserId() throws SelfServiceAuthzException {

        return getUserIDFromUserName(getAuthenticatedUsername(), getTenantId());
    }

    private String getAuthenticatedUsername() {

        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
    }

}
