package com.virgilsecurity.sdk.client;

import java.util.ArrayList;
import java.util.List;

public class ValidationResult {

    private List<String> errors;

    public ValidationResult() {
        errors = new ArrayList<>();
    }

    public boolean isValid() {
        return errors.isEmpty();
    }

    public void addError(String message) {
        this.errors.add(message);
    }
}
