package com.tbudis.security.exception;

/**
 * JWT Authentication exception.
 * Use this class to throw / produce new exception regarding to authenticate process
 */
public class AuthenticationException extends Exception {

   public AuthenticationException(){
       super();
   }

   public AuthenticationException(String message) {
       super(message);
   }
}
