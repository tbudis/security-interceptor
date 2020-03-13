package com.tbudis.security.jwt;

import com.tbudis.security.exception.AuthenticationException;
import com.tbudis.security.vo.UserVO;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * JWT Filter.
 *
 * @author titus
 */
public class JWTFilter {

    /** Reusable JWT filter instance. */
    private static JWTFilter jwtFilter;

    private Logger logger = LoggerFactory.getLogger(this.getClass());

    private JwtParser jwtParser;

    /**
     * Private constructor
     */
    private JWTFilter() {
        jwtParser = Jwts.parser().setSigningKeyResolver(new MultipleSigningKeyResolver());
    }

    /**
     * Get singleton instance of JWT Filter.
     *
     * @return
     */
    public static JWTFilter getInstance() {
        if (jwtFilter == null) {
            jwtFilter = new JWTFilter();
        }
        return jwtFilter;
    }

    /**
     * Verify jwt access token.
     *
     * @param jwt access token in jwt format
     * @return
     * @throws AuthenticationException
     */
    public UserVO authenticate(String jwt) throws AuthenticationException {
        return authenticate(jwt, null);
    }

    /**
     * Verify jwt access token.
     *
     * @param jwt access token in jwt format
     * @param audience supported audience string (optional)
     * @return
     * @throws AuthenticationException
     */
    public UserVO authenticate(String jwt, String audience) throws AuthenticationException {
        if (jwt == null) {
            throw new AuthenticationException("Invalid token !!!");
        }

        // ignore 'Bearer' prefix
        if (jwt.startsWith("Bearer ")) {
            jwt = jwt.substring(jwt.indexOf(" "));
        }

        Claims c;
        try {
            Jws<Claims> jws = jwtParser.parseClaimsJws(jwt);
            c = jws.getBody();
        } catch (ExpiredJwtException e) {
            logger.error(e.getMessage());
            throw new AuthenticationException("Token has been expired !!!");
        } catch (Exception e) {
            logger.error(e.getMessage());
            throw new AuthenticationException("Invalid token !!!");
        }

        if (c != null) {
            if (StringUtils.isNotBlank(audience)) {
                // TODO implement tighter checking
                if (!c.getAudience().contains(audience)) {
                    throw new AuthenticationException("Invalid audience !!!");
                }
            }

            // compose returned object
            UserVO vo = new UserVO();
            vo.setId(NumberUtils.toInt(c.getId(), 0));
            vo.setAuth0Id(c.getSubject());
            vo.setIssuer(c.getIssuer());

            return vo;
        } else {
            throw new AuthenticationException("Can't parse token !!!");
        }
    }
}
