package com.virgilsecurity.sdk.web;

public interface AccessToken {

    String stringRepresentation();

    String identity();

    boolean isExpired();
}
