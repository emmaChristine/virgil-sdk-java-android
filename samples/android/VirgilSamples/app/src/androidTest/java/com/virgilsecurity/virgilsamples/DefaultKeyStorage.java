package com.virgilsecurity.virgilsamples;

import android.app.Activity;
import android.app.Application;
import android.content.Context;
import android.util.Log;

import com.virgilsecurity.sdk.storage.KeyEntry;
import com.virgilsecurity.sdk.storage.KeyStorage;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by Andrii Iakovenko.
 */

public class DefaultKeyStorage implements KeyStorage {

    private static final String TAG = "DefaultKeyStorage";
    @Override
    public void store(KeyEntry keyEntry) {
        try {

            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null);

            String alias = keyEntry.getName();
            SecretKey key = new SecretKeySpec(keyEntry.getValue(), "RSA");
            KeyStore.Entry entry = new KeyStore.SecretKeyEntry(key);
            KeyStore.PasswordProtection pass = new KeyStore.PasswordProtection("fedsgjk".toCharArray());
            ks.setEntry(alias, entry, pass);
            Enumeration<String> aliases  = ks.aliases();
            ks.size();
        } catch (Exception e) {
            Log.e(TAG, "Key entry is not saved", e);
        }
    }

    @Override
    public KeyEntry load(String keyName) {
        return null;
    }

    @Override
    public boolean exists(String keyName) {
        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null);
            Enumeration<String> aliases  = ks.aliases();
            return ks.containsAlias(keyName);
        } catch (Exception e) {
            Log.e(TAG, "Can't check if key entry exists", e);
        }
        return false;
    }

    @Override
    public void delete(String keyName) {

    }
}
