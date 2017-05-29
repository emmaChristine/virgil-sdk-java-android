/*
 * Copyright (c) 2017, Virgil Security, Inc.
 *
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of virgil nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package com.virgilsecurity.secureenclave;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;

import com.virgilsecurity.sdk.crypto.Crypto;
import com.virgilsecurity.sdk.crypto.Fingerprint;
import com.virgilsecurity.sdk.crypto.HashAlgorithm;
import com.virgilsecurity.sdk.crypto.KeyPair;
import com.virgilsecurity.sdk.crypto.KeysType;
import com.virgilsecurity.sdk.crypto.PrivateKey;
import com.virgilsecurity.sdk.crypto.PublicKey;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.SignatureIsNotValidException;
import com.virgilsecurity.sdk.crypto.exceptions.VirgilException;
import com.virgilsecurity.sdk.exception.NullArgumentException;
import com.virgilsecurity.secureenclave.exceptions.ASN1Exception;
import com.virgilsecurity.secureenclave.exceptions.MethodNotAllowedException;
import com.virgilsecurity.secureenclave.model.KeyAdaptor;
import com.virgilsecurity.secureenclave.model.NativeFingerprint;
import com.virgilsecurity.secureenclave.model.PrivateKeyAdaptor;
import com.virgilsecurity.secureenclave.model.PublicKeyAdaptor;
import com.virgilsecurity.secureenclave.model.asn1.Envelope;
import com.virgilsecurity.secureenclave.model.asn1.Nonce;
import com.virgilsecurity.secureenclave.model.asn1.PublicKeyRecipient;
import com.virgilsecurity.secureenclave.model.asn1.VirgilSign;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.crypto.params.KDFParameters;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Andrii Iakovenko
 */
public class NativeCrypto implements Crypto {

    public static final String AES_GCM_NO_PADDING = "AES/GCM/NoPadding";
    public static final String ANDROID_KEY_STORE = "AndroidKeyStore";

    private static final String TAG = "NativeCrypto";
    private static final String SIGN = "VIRGIL-DATA-SIGNATURE";
    private static final int CHUNK_SIZE = 1024;

    private KeysType defaultKeyPairType;

    /**
     * Create new instance of {@link NativeCrypto}.
     */
    public NativeCrypto() {
        defaultKeyPairType = KeysType.EC_BP512R1;
    }

    /**
     * Create new instance of {@link NativeCrypto}.
     *
     * @param defaultKeyPairType
     */
    public NativeCrypto(KeysType defaultKeyPairType) {
        this.defaultKeyPairType = defaultKeyPairType;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#calculateFingerprint(byte[])
     */
    @Override
    public Fingerprint calculateFingerprint(byte[] content) {
        if (content == null) {
            throw new NullArgumentException("content");
        }

        byte[] hash = computeHash(content, HashAlgorithm.SHA256);
        return new NativeFingerprint(hash);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#computeHash(byte[], com.virgilsecurity.sdk.crypto.HashAlgorithm)
     */
    @Override
    public byte[] computeHash(byte[] data, HashAlgorithm algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(getAlgorithmName(algorithm));
            return digest.digest(data);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#decrypt(byte[], com.virgilsecurity.sdk.crypto.PrivateKey)
     */
    @Override
    public byte[] decrypt(byte[] data, PrivateKey privateKey) {
        return internalDecryptThenVerify(data, privateKey, null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#decrypt(java.io.InputStream, java.io.OutputStream,
     * com.virgilsecurity.sdk.crypto.PrivateKey)
     */
    @Override
    public void decrypt(InputStream inputStream, OutputStream outputStream, PrivateKey privateKey) {
        ASN1InputStream stream = new ASN1InputStream(inputStream);
        try {
            ASN1Primitive p = stream.readObject();

            Envelope envelope = Envelope.getInstance(p);

            byte[] decryptedSymmetricKey = decryptSymmetricKey(envelope, privateKey);

            SecretKeySpec skeySpec = new SecretKeySpec(decryptedSymmetricKey, KeyProperties.KEY_ALGORITHM_AES);

            byte[] iv = envelope.getNonce().getContent();

            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(iv));

            try (CipherInputStream cis = new CipherInputStream(stream, cipher)) {

                copyStream(cis, outputStream, CHUNK_SIZE);
            }
        } catch (Exception e) {
            throw new ASN1Exception(e.getMessage());
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#encrypt(byte[], com.virgilsecurity.sdk.crypto.PublicKey)
     */
    @Override
    public byte[] encrypt(byte[] data, PublicKey recipient) {
        return encrypt(data, new PublicKey[]{recipient});
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#encrypt(byte[], com.virgilsecurity.sdk.crypto.PublicKey[])
     */
    @Override
    public byte[] encrypt(byte[] data, PublicKey[] recipients) {
        return internalSignThenEncrypt(data, null, recipients);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#encrypt(java.io.InputStream, java.io.OutputStream,
     * com.virgilsecurity.sdk.crypto.PublicKey)
     */
    @Override
    public void encrypt(InputStream inputStream, OutputStream outputStream, PublicKey recipient) {
        encrypt(inputStream, outputStream, new PublicKey[]{recipient});
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#encrypt(java.io.InputStream, java.io.OutputStream,
     * com.virgilsecurity.sdk.crypto.PublicKey[])
     */
    @Override
    public void encrypt(InputStream inputStream, OutputStream outputStream, PublicKey[] recipients) {
        Map<String, Object> customParams = new HashMap<>();

        SecureRandom rnd = new SecureRandom();
        byte[] randomKey = new byte[32];
        byte[] nonce = new byte[12];

        rnd.nextBytes(randomKey);
        rnd.nextBytes(nonce);

        byte[] envelope = makeEnvelope(randomKey, recipients, customParams, nonce);

        try {
            SecretKeySpec skeySpec = new SecretKeySpec(randomKey, KeyProperties.KEY_ALGORITHM_AES);
            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(nonce));

            outputStream.write(envelope);
            try (CipherOutputStream cos = new CipherOutputStream(outputStream, cipher)) {
                copyStream(inputStream, cos, CHUNK_SIZE);
            }
        } catch (Exception e) {
            throw new VirgilException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#exportPrivateKey(com.virgilsecurity.sdk.crypto.PrivateKey)
     */
    @Override
    public byte[] exportPrivateKey(PrivateKey privateKey) {
        throw new MethodNotAllowedException();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#exportPrivateKey(com.virgilsecurity.sdk.crypto.PrivateKey,
     * java.lang.String)
     */
    @Override
    public byte[] exportPrivateKey(PrivateKey privateKey, String password) {
        throw new MethodNotAllowedException();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#exportPublicKey(com.virgilsecurity.sdk.crypto.PublicKey)
     */
    @Override
    public byte[] exportPublicKey(PublicKey publicKey) {
        return exportPublicKey(publicKey.getValue());
    }

    private byte[] exportPublicKey(byte[] publicKeyValue) {
        EncodedKeySpec spec = new X509EncodedKeySpec(publicKeyValue);
        return spec.getEncoded();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#extractPublicKey(com.virgilsecurity.sdk.crypto.PrivateKey)
     */
    @Override
    public PublicKey extractPublicKey(PrivateKey privateKey) {
        if (!(privateKey instanceof KeyAdaptor)) {
            throw new IllegalArgumentException("Only native private keys supported");
        }
        KeyStore.PrivateKeyEntry entry = loadKestoreEntry(privateKey.getId());
        java.security.PublicKey publicKey = entry.getCertificate().getPublicKey();
        byte[] recipientId = computePublicKeyHash(publicKey.getEncoded());

        return new PublicKeyAdaptor(recipientId, publicKey);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#generateKeys()
     */
    @Override
    public KeyPair generateKeys() {
        String id = UUID.randomUUID().toString();
        try {
            KeyPairGenerator kpg;
            switch (defaultKeyPairType) {
                case RSA_2048:
                case RSA_3072:
                case RSA_4096:
                case RSA_8192:
                    kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEY_STORE);
                    kpg.initialize(new KeyGenParameterSpec.Builder
                            (id, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                            .setDigests(KeyProperties.DIGEST_SHA384)
                            .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                            .build());
                    break;
                case EC_SECP256K1:
                case EC_SECP256R1:
                case EC_SECP384R1:
                case EC_SECP521R1:
                    kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE);
                    kpg.initialize(new KeyGenParameterSpec.Builder(
                            id,
                            KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                            .setDigests(KeyProperties.DIGEST_SHA384,
                                    KeyProperties.DIGEST_SHA512)
                            .build());
                    break;
                default:
                    throw new NoSuchAlgorithmException();
            }
            java.security.KeyPair generatedKeyPair = kpg.generateKeyPair();

            KeyPair keyPair = new KeyPair();

            byte[] recipientId = computePublicKeyHash(generatedKeyPair.getPublic().getEncoded());
            keyPair.setPublicKey(new PublicKeyAdaptor(recipientId, generatedKeyPair.getPublic()));
            keyPair.setPrivateKey(new PrivateKeyAdaptor(id, recipientId, generatedKeyPair.getPrivate()));

            return keyPair;
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public PrivateKey getPrivateKey(String privateKeyId) {
        KeyStore.PrivateKeyEntry entry = loadKestoreEntry(privateKeyId);
        java.security.PrivateKey privateKey = entry.getPrivateKey();
        java.security.PublicKey publicKey = entry.getCertificate().getPublicKey();

        byte[] recipientId = computePublicKeyHash(publicKey.getEncoded());

        return new PrivateKeyAdaptor(privateKeyId, recipientId, privateKey);
    }

    private KeyStore.PrivateKeyEntry loadKestoreEntry(String privateKeyId) {
        try {
            KeyStore ks = KeyStore.getInstance(ANDROID_KEY_STORE);
            ks.load(null);

            KeyStore.Entry entry = ks.getEntry(privateKeyId, null);
            if (entry == null) {
                throw new CryptoException("Key not found");
            }
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                throw new CryptoException("Not an instance of a PrivateKeyEntry");
            }

            return (KeyStore.PrivateKeyEntry) entry;
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#importPrivateKey(byte[])
     */
    @Override
    public PrivateKey importPrivateKey(byte[] keyData) {
        throw new MethodNotAllowedException();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#importPrivateKey(byte[], java.lang.String)
     */
    @Override
    public PrivateKey importPrivateKey(byte[] keyData, String password) {
        throw new MethodNotAllowedException();
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#importPublicKey(byte[])
     */
    @Override
    public PublicKey importPublicKey(byte[] publicKey) {
        EncodedKeySpec spec =
                new X509EncodedKeySpec(publicKey);
        try {
            KeyFactory kf;
            //TODO find more suitable way to detect key type
            if (publicKey.length > 250) {
                kf = KeyFactory.getInstance("RSA");
            } else {
                kf = KeyFactory.getInstance("EC");
            }
            java.security.PublicKey importedPublicKey = kf.generatePublic(spec);
            byte[] id = computePublicKeyHash(importedPublicKey.getEncoded());
            return new PublicKeyAdaptor(id, importedPublicKey);
        } catch (Exception e) {
            Log.d(TAG, "Pubic key import error", e);
            throw new CryptoException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#sign(byte[], com.virgilsecurity.sdk.crypto.PrivateKey)
     */
    @Override
    public byte[] sign(byte[] data, PrivateKey privateKey) {
        if (data == null) {
            throw new NullArgumentException("data");
        }

        if (privateKey == null) {
            throw new NullArgumentException("privateKey");
        }
        if (!(privateKey instanceof PrivateKeyAdaptor)) {
            throw new IllegalArgumentException("Private key should be a private key adaptor");
        }

        try {
            java.security.PrivateKey pk = (java.security.PrivateKey) ((PrivateKeyAdaptor) privateKey).getWrapped();

            Signature signature = Signature.getInstance(getSignatureAlgByKey(pk));
            signature.initSign(pk);
            signature.update(data);

            byte[] sign = signature.sign();
            byte[] encodedSign = new VirgilSign(sign).toASN1Primitive().getEncoded(ASN1Encoding.DER);
            return encodedSign;
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#sign(java.io.InputStream, com.virgilsecurity.sdk.crypto.PrivateKey)
     */
    @Override
    public byte[] sign(InputStream inputStream, PrivateKey privateKey) {
        if (inputStream == null) {
            throw new NullArgumentException("inputStream");
        }

        if (privateKey == null) {
            throw new NullArgumentException("privateKey");
        }
        if (!(privateKey instanceof PrivateKeyAdaptor)) {
            throw new IllegalArgumentException("Private key should be a private key adaptor");
        }

        try {
            java.security.PrivateKey pk = (java.security.PrivateKey) ((PrivateKeyAdaptor) privateKey).getWrapped();

            Signature signature = Signature.getInstance(getSignatureAlgByKey(pk));
            signature.initSign(pk);

            byte[] block = new byte[CHUNK_SIZE];
            int i;
            while ((i = inputStream.read(block)) != -1) {
                signature.update(block, 0, i);
            }

            byte[] sign = signature.sign();
            byte[] encodedSign = new VirgilSign(sign).toASN1Primitive().getEncoded(ASN1Encoding.DER);
            return encodedSign;
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#verify(byte[], byte[], com.virgilsecurity.sdk.crypto.PublicKey)
     */
    @Override
    public boolean verify(byte[] data, byte[] signature, PublicKey signer) {
        boolean isValid = true;
        try {
            java.security.PublicKey publicKey = (java.security.PublicKey) ((PublicKeyAdaptor) signer).getWrapped();

            byte[] sign = VirgilSign.getInstance(signature).getSign();

            Signature sig = Signature.getInstance(getSignatureAlgByKey(publicKey));
            sig.initVerify(publicKey);
            sig.update(data);

            isValid = sig.verify(sign);
        } catch (Throwable e) {
            Log.d(TAG, "Verification error", e);
        }

        return isValid;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#verify(java.io.InputStream, byte[],
     * com.virgilsecurity.sdk.crypto.PublicKey)
     */
    @Override
    public boolean verify(InputStream inputStream, byte[] signature, PublicKey signer) {
        boolean isValid = true;
        try {
            java.security.PublicKey publicKey = (java.security.PublicKey) ((PublicKeyAdaptor) signer).getWrapped();

            byte[] sign = VirgilSign.getInstance(signature).getSign();

            Signature sig = Signature.getInstance(getSignatureAlgByKey(publicKey));
            sig.initVerify(publicKey);

            byte[] block = new byte[CHUNK_SIZE];
            int i;
            while ((i = inputStream.read(block)) != -1) {
                sig.update(block, 0, i);
            }

            isValid = sig.verify(sign);
        } catch (Throwable e) {
            Log.d(TAG, "Verification error", e);
        }

        return isValid;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#signThenEncrypt(byte[], com.virgilsecurity.sdk.crypto.PrivateKey,
     * com.virgilsecurity.sdk.crypto.PublicKey)
     */
    @Override
    public byte[] signThenEncrypt(byte[] data, PrivateKey privateKey, PublicKey recipient) {
        return internalSignThenEncrypt(data, privateKey, new PublicKey[]{recipient});
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#signThenEncrypt(byte[], com.virgilsecurity.sdk.crypto.PrivateKey,
     * com.virgilsecurity.sdk.crypto.PublicKey[])
     */
    @Override
    public byte[] signThenEncrypt(byte[] data, PrivateKey privateKey, PublicKey[] recipients) {
        return internalSignThenEncrypt(data, privateKey, recipients);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#decryptThenVerify(byte[], com.virgilsecurity.sdk.crypto.PrivateKey,
     * com.virgilsecurity.sdk.crypto.PublicKey)
     */
    @Override
    public byte[] decryptThenVerify(byte[] cipherData, PrivateKey privateKey, PublicKey publicKey) {
        return internalDecryptThenVerify(cipherData, privateKey, publicKey);
    }

    /**
     * @param publicKey
     * @return
     */
    private byte[] computePublicKeyHash(byte[] publicKey) {
        byte[] publicKeyDER = exportPublicKey(publicKey);
        return this.computeHash(publicKeyDER, HashAlgorithm.SHA256);
    }

    public static String getAlgorithmName(HashAlgorithm algorithm) {
        switch (algorithm) {
            case MD5:
                return "MD5";
            case SHA1:
                return "SHA-1";
            case SHA224:
                return "SHA-224";
            case SHA256:
                return "SHA-256";
            case SHA384:
                return "SHA-384";
            case SHA512:
                return "SHA-512";
        }
        return "SHA-256";
    }

    private String getSignatureAlgByKey(Key key) {
        if (KeyProperties.KEY_ALGORITHM_RSA.equalsIgnoreCase(key.getAlgorithm())) {
            return "SHA384withRSA";
        } else {
            return "SHA384withECDSA";
        }
    }

    private String getTransformationByKey(Key key) {
        if (KeyProperties.KEY_ALGORITHM_RSA.equalsIgnoreCase(key.getAlgorithm())) {
            return "RSA/ECB/PKCS1Padding";
        } else {
            return "RSA/ECB/OAEPPadding";
        }
    }

    public static String getKeyName(KeysType keysType) {
        return null;
    }

    private PrivateKeyAdaptor checkPrivateKey(PrivateKey privateKey) {
        if (privateKey == null) {
            throw new NullArgumentException("privateKey");
        }
        if (!(privateKey instanceof PrivateKeyAdaptor)) {
            throw new IllegalArgumentException("privateKey");
        }
        return (PrivateKeyAdaptor) privateKey;
    }

    private PublicKeyAdaptor checkPublicKey(PublicKey publicKey) {
        if (publicKey == null) {
            throw new NullArgumentException("publicKey");
        }
        if (!(publicKey instanceof PublicKeyAdaptor)) {
            throw new IllegalArgumentException("publicKey");
        }
        return (PublicKeyAdaptor) publicKey;
    }

    private byte[] decryptSymmetricKey(Envelope envelope, PrivateKey privateKey) {
        PrivateKeyAdaptor pk = checkPrivateKey(privateKey);

        for (ASN1Encodable recipient : envelope.getRecipients()) {
            if (recipient != null) {
                PublicKeyRecipient rec = (PublicKeyRecipient) recipient;

                if (Arrays.equals(privateKey.getRecipientId(), (rec.getId()))) {

                    if (KeyProperties.KEY_ALGORITHM_RSA.equals(pk.getWrapped().getAlgorithm())) {
                        try {
                            String transformation = getTransformationByKey(pk.getWrapped());
                            Cipher cipher = Cipher.getInstance(transformation);
                            cipher.init(Cipher.DECRYPT_MODE, pk.getWrapped());
                            byte[] decryptedSymmetricKey = cipher.doFinal(rec.getEncryptedSymmetricKey());
                            return decryptedSymmetricKey;
                        } catch (Exception e) {
                            throw new VirgilException(e);
                        }
                    } else if (KeyProperties.KEY_ALGORITHM_EC.equals(pk.getWrapped().getAlgorithm())) {
                        try {
                            //TODO symmetric key decription for EC
                            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(rec.getEphemeralPublicKey());
                            KeyFactory kf = KeyFactory.getInstance("EC");
                            java.security.PublicKey importedPublicKey = kf.generatePublic(keySpec);

                            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", ANDROID_KEY_STORE);
                            keyAgreement.init(pk.getWrapped());
                            keyAgreement.doPhase(importedPublicKey, true);
                            byte[] shared = keyAgreement.generateSecret();

                            KDF2BytesGenerator kdf = new KDF2BytesGenerator(new SHA384Digest());
                            kdf.init(new KDFParameters(shared, null));
                            byte[] derivedKeys = new byte[80];
                            kdf.generateBytes(derivedKeys, 0, 80); // 32 bytes - AES key + 48 bytes HMAC key

                            byte[] aesKey = Arrays.copyOfRange(derivedKeys, 0, 32);
                            byte[] hmacKey = Arrays.copyOfRange(derivedKeys, 32, 80);

                            SecretKeySpec hmacSpec = new SecretKeySpec(hmacKey, KeyProperties.KEY_ALGORITHM_HMAC_SHA384);
                            Mac mac = Mac.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA384);
                            mac.init(hmacSpec);
                            byte[] tag = mac.doFinal(rec.getEncryptedSymmetricKey());
                            if (!Arrays.equals(tag, rec.getTag())) {
                                throw new IllegalArgumentException("Tag");
                            }

                            SecretKeySpec aesSpec = new SecretKeySpec(aesKey, KeyProperties.KEY_ALGORITHM_AES);
                            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
                            cipher.init(Cipher.DECRYPT_MODE, aesSpec, new IvParameterSpec(rec.getIv()));
                            byte[] decryptedSymmetricKey = cipher.doFinal(rec.getEncryptedSymmetricKey());
                            return decryptedSymmetricKey;
                        } catch (Exception e) {
                            throw new VirgilException(e);
                        }
                    }
                }
            }
        }

        throw new IllegalArgumentException("privateKey");
    }

    private byte[] internalDecryptThenVerify(byte[] data, PrivateKey privateKey, PublicKey publicKey) {
        ASN1InputStream stream = new ASN1InputStream(data);
        ASN1Primitive p = null;
        try {
            p = stream.readObject();

            Envelope envelope = Envelope.getInstance(p);

            byte[] decryptedSymmetricKey = decryptSymmetricKey(envelope, privateKey);

            int available = stream.available();
            byte[] ciphertext = Arrays.copyOfRange(data, data.length - available, data.length);

            SecretKeySpec skeySpec = new SecretKeySpec(decryptedSymmetricKey, KeyProperties.KEY_ALGORITHM_AES);

            byte[] iv = envelope.getNonce().getContent();

            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, new IvParameterSpec(iv));
            byte[] plaintext = cipher.doFinal(ciphertext);

            if (publicKey != null) {
                if (!envelope.getCustomParams().containsKey(SIGN)) {
                    throw new IllegalArgumentException("signature");
                }
                boolean isValid = verify(plaintext, (byte[]) envelope.getCustomParams().get(SIGN), publicKey);
                if (!isValid) {
                    throw new SignatureIsNotValidException();
                }
            }
            return plaintext;
        } catch (SignatureIsNotValidException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }

    private byte[] internalSignThenEncrypt(byte[] data, PrivateKey privateKey, PublicKey[] recipients) {
        Map<String, Object> customParams = new HashMap<>();
        if (privateKey != null) {
            //first, sign the plaintext if we have a private key
            customParams.put(SIGN, sign(data, privateKey));
        }

        SecureRandom rnd = new SecureRandom();
        byte[] randomKey = new byte[32];
        byte[] nonce = new byte[12];

        rnd.nextBytes(randomKey);
        rnd.nextBytes(nonce);

        byte[] envelope = makeEnvelope(randomKey, recipients, customParams, nonce);

        byte[] ciphertext = null;
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(randomKey, KeyProperties.KEY_ALGORITHM_AES);
            Cipher cipher = Cipher.getInstance(AES_GCM_NO_PADDING);
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec(nonce));
            ciphertext = cipher.doFinal(data);
        } catch (Exception e) {
            throw new VirgilException(e);
        }

        byte[] message = addAll(envelope, ciphertext);
        return message;
    }

    private byte[] makeEnvelope(byte[] key, PublicKey[] recipients, Map<String, Object> customParam, byte[] nonce) {
        List<ASN1Encodable> recs = new ArrayList<>();
        for (PublicKey recipient : recipients) {

            PublicKeyAdaptor publicKey = checkPublicKey(recipient);
            PublicKeyRecipient rec = encryptSymmetricKey(publicKey.getRecipientId(), (java.security.PublicKey) publicKey.getWrapped(), key);
            recs.add(rec);
        }

        Nonce nonceModel = new Nonce(nonce);

        try {
            byte[] envelope = new Envelope(recs, nonceModel, customParam).toASN1Primitive().getEncoded();
            return envelope;
        } catch (IOException e) {
            throw new VirgilException(e);
        }
    }

    private PublicKeyRecipient encryptSymmetricKey(byte[] id, java.security.PublicKey publicKey, byte[] symmetricKey) {
        if (publicKey == null) {
            throw new NullArgumentException("publicKey");
        }
        if (symmetricKey == null) {
            throw new NullArgumentException("symmetricKey");
        }

        try {
            String transformation = getTransformationByKey(publicKey);
            Cipher cipher = Cipher.getInstance(transformation);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedSymmetricKey = cipher.doFinal(symmetricKey);

            return new PublicKeyRecipient(publicKey.getAlgorithm(), id, encryptedSymmetricKey);
        } catch (Exception e) {
            throw new VirgilException(e);
        }
    }

    private byte[] addAll(byte[] array1, byte[] array2) {
        byte[] joinedArray = new byte[array1.length + array2.length];
        System.arraycopy(array1, 0, joinedArray, 0, array1.length);
        System.arraycopy(array2, 0, joinedArray, array1.length, array2.length);
        return joinedArray;
    }

    private void copyStream(InputStream inputStream, OutputStream outputStream, int chunkSize) throws IOException {
        byte[] block = new byte[chunkSize];
        int i;
        while ((i = inputStream.read(block)) != -1) {
            outputStream.write(block, 0, i);
        }
    }

}
