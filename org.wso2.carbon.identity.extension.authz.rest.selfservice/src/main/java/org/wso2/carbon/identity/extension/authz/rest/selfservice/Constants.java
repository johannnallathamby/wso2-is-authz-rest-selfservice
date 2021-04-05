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

package org.wso2.carbon.identity.extension.authz.rest.selfservice;

/**
 * Self-service Authorization constants and error codes.
 */
public class Constants {

    public static final String REQUEST_WRAPPER = "request-wrapper";
    public static final String SCIM2_ROLES = "/scim2/Groups";
    public static final String FILTER_QUERY_PARAM_NAME = "filter";
    public static final String ROLE_FILTER_QUERY_STRING = "displayName sw #";
    public static final String DEFAULT_ROLE_PREFIX = "APP_";
    public static final String HTTP_GET = "GET";
    public static final String HTTP_PATCH = "PATCH";

    public static final String MGT_ROLES_REGISTRY_RESOURCE = "/identity/selfservicerestauthz";
    public static final String MGT_ROLES_REGISTRY_PROPERTY = "selfServiceRolePrefix";

    public static final String PATCH_PATH_USERS = "users";

    public static final String AUTH_CONTEXT = "auth-context";
    public static final String ROLE_UPDATE_PERMISSION = "/permission/admin/manage/identity/rolemgt/update";
    public static final String ROLE_VIEW_PERMISSION = "/permission/admin/manage/identity/rolemgt/view";
    public static final String UI_EXECUTE = "ui.execute";

    public enum ErrorMessages {

        // Client errors (SELF-SERVICE-REST-AUTHZ-60001 - SELF-SERVICE-REST-AUTHZ-60999)
        GET_MGT_ROLES_UNSUPPORTED_ENCODING_ERROR("SELF-SERVICE-REST-AUTHZ-60014",
                "Unsupported encoding in filter", "Unsupported encoding in filter."),

        // Server errors (SELF-SERVICE-REST-AUTHZ-65001 - SELF-SERVICE-REST-AUTHZ-65999)
        GET_MGT_ROLES_REGISTRY_ERROR(
                "SELF-SERVICE-REST-AUTHZ-65002", "Error accessing the registry.",
                "Error accessing the config registry : %s"),
        ROLE_MGT_SERVICE_ERROR("SELF-SERVICE-REST-AUTHZ-60007",
                "Role management error.", "Role management error. %s"),
        USER_STORE_OPERATONS_ERROR("SELF-SERVICE-REST-AUTHZ-60008",
                "USer store operations error", "USer store operations error. %s");

        private final String code;
        private final String message;
        private final String description;

        ErrorMessages(String code, String message, String description) {

            this.code = code;
            this.message = message;
            this.description = description;
        }

        public String getCode() {

            return code;
        }

        public String getMessage() {

            return message;
        }

        public String getDescription() {

            return description;
        }
    }

    /**
     * Forbidden Error Messages
     */
    public enum ForbiddenErrorMessages {

        SELF_SERVICE_REST_AUTHZ_60001
    }

    /**
     * Not Found Error Messages
     */
    public enum NotFoundErrorMessages {

    }

    /**
     * Conflict Error Messages
     */
    public enum ConflictErrorMessages {

        SELF_SERVICE_REST_AUTHZ_60008, SELF_SERVICE_REST_AUTHZ_60010
    }
}
