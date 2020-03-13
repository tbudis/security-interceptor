package com.tbudis.security.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwsHeader;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SigningKeyResolverAdapter;

import java.security.Key;

/**
 * Handle various ways to sign JWT with different keys.
 * Ref: https://github.com/jwtk/jjwt#jws-read-key-resolver
 *
 * @author titus
 */
public class MultipleSigningKeyResolver extends SigningKeyResolverAdapter {

    @Override
    public Key resolveSigningKey(JwsHeader header, Claims claims) {
        Key key = null;

        if (SignatureAlgorithm.HS256.getValue().equals(header.getAlgorithm())) {
            // Auth0 secret key
            key = Keys.secretKey;
        } else if (SignatureAlgorithm.RS256.getValue().equals(header.getAlgorithm())) {
            // Auth0 public key
            key = Keys.publicKey;
        }

        // default
        if (key == null) {
            key = super.resolveSigningKey(header, claims);
        }

        return key;
    }
}
