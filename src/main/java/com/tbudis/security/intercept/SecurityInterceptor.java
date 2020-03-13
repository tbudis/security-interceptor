package com.tbudis.security.intercept;

import com.tbudis.security.annotation.Secured;
import com.tbudis.security.exception.AuthenticationException;
import com.tbudis.security.jwt.JWTFilter;
import com.tbudis.security.var.RoleName;
import com.tbudis.security.vo.UserVO;

import org.jboss.resteasy.spi.ResteasyProviderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * Intercept requests to each protected resource.
 * Authenticate JWT access token and the user permissions (if any).
 *
 * @author titus
 */
@Provider
public class SecurityInterceptor implements ContainerRequestFilter {

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    @Context
    private ResourceInfo resourceInfo;

    public void filter(ContainerRequestContext containerRequestContext) {

        Secured secured = resourceInfo.getResourceMethod().getAnnotation(Secured.class);
        if (secured == null) secured = resourceInfo.getResourceClass().getAnnotation(Secured.class);

        if (secured != null) {
            String jwt = containerRequestContext.getHeaderString("Authorization");

            UserVO userVo = null;
            try {
                userVo = JWTFilter.getInstance().authenticate(jwt, secured.aud());

                boolean allowed = userHasPermission(secured.roles(), userVo.getRoles());
                if (!allowed) {
                    throw new AuthenticationException("No permission to access resource");
                }

                // push the user object to the request context
                ResteasyProviderFactory.pushContext(UserVO.class, userVo);

            } catch (AuthenticationException e) {
                logger.warn("AuthenticationException [reason: {}, user: {}, roles: {}, resource: {}, permissions: {}]",
                        e.getMessage(),
                        (userVo != null) ? userVo.getEmail() : null,
                        (userVo != null) ? userVo.getRoles() : null,
                        resourceInfo.getResourceMethod().getName(),
                        Arrays.asList(secured.roles()));

                Map<String, Object> map = new HashMap();
                map.put("status", false);
                map.put("reason", e.getMessage());

                Response.ResponseBuilder builder = Response.status(Response.Status.FORBIDDEN).entity(map);
                throw new WebApplicationException(builder.build());
            }
        }
    }

    /**
     * Check whether the specified user has permission to access the resource.
     *
     * @param allowedRoles
     * @param userCombinedRoles
     * @return
     */
    private boolean userHasPermission(RoleName[] allowedRoles, int userCombinedRoles) {

        // if roles list is empty, the resource doesn't require specific permission
        boolean allowed = (allowedRoles.length == 0);

        // if roles list is not empty, find minimal 1 matched role - permission
        for (RoleName roleName : allowedRoles) {
            if (roleName.isAllowed(userCombinedRoles)) {
                allowed = true;
                break;
            }
        }

        return allowed;
    }
}
