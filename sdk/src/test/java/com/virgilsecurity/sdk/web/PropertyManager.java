package com.virgilsecurity.sdk.web;

import org.apache.commons.lang.StringUtils;

public class PropertyManager {

    protected String APP_ID = getPropertyByName("APP_ID");
    protected String ACCOUNT_ID = getPropertyByName("ACCOUNT_ID");
    protected String APP_PRIVATE_KEY_PASSWORD = getPropertyByName("APP_PRIVATE_KEY_PASSWORD");
    protected String APP_PRIVATE_KEY = StringUtils.replace(getPropertyByName("APP_PRIVATE_KEY"), "\\n", "\n");
    protected String API_PRIVATE_KEY = StringUtils.replace(getPropertyByName("API_PRIVATE_KEY"), "\\n", "\n");
    protected String CARD_SERVICE_ADDRESS = getPropertyByName("CARD_SERVICE_ADDRESS");

    public String getPropertyByName(String propertyName) {
        boolean isMacOs = System.getProperty("os.name")
                                .toLowerCase()
                                .startsWith("mac os x");
        if (isMacOs) {
            if (StringUtils.isBlank(System.getenv(propertyName))) {
                return null;
            }

            return System.getenv(propertyName);
        } else {
            if (StringUtils.isBlank(System.getProperty(propertyName))) {
                return null;
            }

            return System.getProperty(propertyName);
        }

    }
}
