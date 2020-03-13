package com.tbudis.security.annotation;

import com.tbudis.security.var.RoleName;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Java annotation for describing security attributes.
 *
 * @author tbudis
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
public @interface Secured {

    /**
     * Annotation attribute to hold the audience information.
     * This attributes is optional. If left empty, this will allow all audiences.
     *
     * @return
     */
    public String aud() default "";

    /**
     * Annotation attribute to hold the list of security roles.
     *
     * @return The security roles
     */
    public RoleName[] roles() default {};

}
