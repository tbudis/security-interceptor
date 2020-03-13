package com.tbudis.security.var;

/**
 * Role name enumeration.
 * Support up to 31 different roles in an int variable (32 bit).
 *
 * @author titus
 */
public enum RoleName {

    NOT_DEFINED("Not Defined"),     // value = 0
    ADMIN("Admin"),                 // value = 1
    POWER_USER("Power User"),       // value = 2
    ACCOUNT_ADMIN("Account Admin"), // value = 4
    ACCOUNT_USER("Account User");   // value = 8

    private String label;

    RoleName(String label) {
        this.label = label;
    }

    public String getLabel() {
        return label;
    }

    public int value() {
        if (this.ordinal() == 0) {
            return 0;
        }

        return 1 << (this.ordinal() - 1);
    }

    public boolean isAllowed(int roles) {
        return (roles & this.value()) != 0;
    }
}
