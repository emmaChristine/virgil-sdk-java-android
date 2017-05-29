/*
 * Copyright (c) 2016, Virgil Security, Inc.
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
package com.virgilsecurity.sdk.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import com.virgilsecurity.crypto.VirgilCipher;
import com.virgilsecurity.crypto.VirgilCustomParams;
import com.virgilsecurity.crypto.VirgilDataSink;
import com.virgilsecurity.crypto.VirgilDataSource;
import com.virgilsecurity.crypto.VirgilHash;
import com.virgilsecurity.crypto.VirgilHash.Algorithm;
import com.virgilsecurity.crypto.VirgilKeyPair;
import com.virgilsecurity.crypto.VirgilSigner;
import com.virgilsecurity.crypto.VirgilStreamCipher;
import com.virgilsecurity.crypto.VirgilStreamDataSink;
import com.virgilsecurity.crypto.VirgilStreamDataSource;
import com.virgilsecurity.crypto.VirgilStreamSigner;
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException;
import com.virgilsecurity.sdk.crypto.exceptions.DecryptionException;
import com.virgilsecurity.sdk.crypto.exceptions.EncryptionException;
import com.virgilsecurity.sdk.crypto.exceptions.SignatureIsNotValidException;
import com.virgilsecurity.sdk.crypto.exceptions.SigningException;
import com.virgilsecurity.sdk.crypto.exceptions.VerificationException;
import com.virgilsecurity.sdk.exception.MethodNotImplementedException;
import com.virgilsecurity.sdk.exception.NullArgumentException;

/**
 * The Virgil's implementation of Crypto.
 *
 * @author Andrii Iakovenko
 * 
 * @see Crypto
 * @see PublicKey
 * @see PrivateKey
 *
 */
public class VirgilCrypto implements Crypto {

    private static final byte[] CUSTOM_PARAM_SIGNATURE = "VIRGIL-DATA-SIGNATURE".getBytes(StandardCharsets.UTF_8);
    private KeysType defaultKeyPairType;

    /**
     * Create new instance of {@link VirgilCrypto}.
     */
    public VirgilCrypto() {
        this.defaultKeyPairType = KeysType.Default;
    }

    /**
     * Create new instance of {@link VirgilCrypto}.
     * 
     * @param keysType
     */
    public VirgilCrypto(KeysType keysType) {
        this.defaultKeyPairType = keysType;
    }

    public static VirgilHash createVirgilHash(HashAlgorithm algorithm) {
        switch (algorithm) {
        case MD5:
            return new VirgilHash(VirgilHash.Algorithm.MD5);
        case SHA1:
            return new VirgilHash(VirgilHash.Algorithm.SHA1);
        case SHA224:
            return new VirgilHash(VirgilHash.Algorithm.SHA224);
        case SHA256:
            return new VirgilHash(VirgilHash.Algorithm.SHA256);
        case SHA384:
            return new VirgilHash(VirgilHash.Algorithm.SHA384);
        case SHA512:
            return new VirgilHash(VirgilHash.Algorithm.SHA512);
        default:
            throw new IllegalArgumentException();
        }
    }

    public static VirgilKeyPair.Type toVirgilKeyPairType(KeysType keysType) {
        switch (keysType) {
        case Default:
            return VirgilKeyPair.Type.FAST_EC_ED25519;
        case RSA_2048:
            return VirgilKeyPair.Type.RSA_2048;
        case RSA_3072:
            return VirgilKeyPair.Type.RSA_3072;
        case RSA_4096:
            return VirgilKeyPair.Type.RSA_4096;
        case RSA_8192:
            return VirgilKeyPair.Type.RSA_8192;
        case EC_SECP256R1:
            return VirgilKeyPair.Type.EC_SECP256R1;
        case EC_SECP384R1:
            return VirgilKeyPair.Type.EC_SECP384R1;
        case EC_SECP521R1:
            return VirgilKeyPair.Type.EC_SECP521R1;
        case EC_BP256R1:
            return VirgilKeyPair.Type.EC_BP256R1;
        case EC_BP384R1:
            return VirgilKeyPair.Type.EC_BP384R1;
        case EC_BP512R1:
            return VirgilKeyPair.Type.EC_BP512R1;
        case EC_SECP256K1:
            return VirgilKeyPair.Type.EC_SECP256K1;
        case EC_CURVE25519:
            return VirgilKeyPair.Type.EC_CURVE25519;
        case FAST_EC_X25519:
            return VirgilKeyPair.Type.FAST_EC_X25519;
        case FAST_EC_ED25519:
            return VirgilKeyPair.Type.FAST_EC_ED25519;
        }
        assert false; // This should never happen! Some key type missed.
        return VirgilKeyPair.Type.FAST_EC_ED25519;
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

        try (VirgilHash sha256 = new VirgilHash(Algorithm.SHA256)) {
            byte[] hash = sha256.hash(content);
            return new VirgilFingerprint(hash);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#computeHash(byte[], com.virgilsecurity.sdk.crypto.HashAlgorithm)
     */
    @Override
    public byte[] computeHash(byte[] data, HashAlgorithm algorithm) {
        if (data == null) {
            throw new NullArgumentException("data");
        }

        try (VirgilHash hasher = createVirgilHash(algorithm)) {
            return hasher.hash(data);
        }
    }

    /**
     * @param publicKey
     * @return
     */
    private byte[] computePublicKeyHash(byte[] publicKey) {
        byte[] publicKeyDER = VirgilKeyPair.publicKeyToDER(publicKey);
        return this.computeHash(publicKeyDER, HashAlgorithm.SHA256);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#decrypt(byte[], com.virgilsecurity.sdk.crypto.PrivateKey)
     */
    @Override
    public byte[] decrypt(byte[] cipherData, PrivateKey privateKey) {
        try (VirgilCipher cipher = new VirgilCipher()) {
            byte[] decryptedData = cipher.decryptWithKey(cipherData, privateKey.getRecipientId(),
                    privateKey.getValue());
            return decryptedData;
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#decrypt(java.io.InputStream, java.io.OutputStream,
     * com.virgilsecurity.sdk.crypto.PrivateKey)
     */
    @Override
    public void decrypt(InputStream inputStream, OutputStream outputStream, PrivateKey privateKey)
            throws DecryptionException {
        try (VirgilStreamCipher cipher = new VirgilStreamCipher();
                VirgilDataSource dataSource = new VirgilStreamDataSource(inputStream);
                VirgilDataSink dataSink = new VirgilStreamDataSink(outputStream)) {

            cipher.decryptWithKey(dataSource, dataSink, privateKey.getRecipientId(), privateKey.getValue());
        } catch (IOException e) {
            throw new DecryptionException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#decryptThenVerify(byte[], com.virgilsecurity.sdk.crypto.PrivateKey,
     * com.virgilsecurity.sdk.crypto.PublicKey)
     */
    @Override
    public byte[] decryptThenVerify(byte[] cipherData, PrivateKey privateKey, PublicKey publicKey) {
        try (VirgilSigner signer = new VirgilSigner(); VirgilCipher cipher = new VirgilCipher()) {
            byte[] decryptedData = cipher.decryptWithKey(cipherData, privateKey.getRecipientId(),
                    privateKey.getValue());
            byte[] signature = cipher.customParams().getData(CUSTOM_PARAM_SIGNATURE);

            boolean isValid = signer.verify(decryptedData, signature, publicKey.getValue());
            if (!isValid) {
                throw new SignatureIsNotValidException();
            }

            return decryptedData;
        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#encrypt(byte[], com.virgilsecurity.sdk.crypto.PublicKey)
     */
    @Override
    public byte[] encrypt(byte[] data, PublicKey recipient) {
        try (VirgilCipher cipher = new VirgilCipher()) {
            cipher.addKeyRecipient(recipient.getRecipientId(), recipient.getValue());

            byte[] encryptedData = cipher.encrypt(data, true);
            return encryptedData;
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#encrypt(byte[], com.virgilsecurity.sdk.crypto.PublicKey[])
     */
    @Override
    public byte[] encrypt(byte[] data, PublicKey[] recipients) {
        try (VirgilCipher cipher = new VirgilCipher()) {
            for (PublicKey recipient : recipients) {
                cipher.addKeyRecipient(recipient.getRecipientId(), recipient.getValue());
            }

            byte[] encryptedData = cipher.encrypt(data, true);
            return encryptedData;
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#encrypt(java.io.InputStream, java.io.OutputStream,
     * com.virgilsecurity.sdk.crypto.PublicKey)
     */
    @Override
    public void encrypt(InputStream inputStream, OutputStream outputStream, PublicKey recipient)
            throws EncryptionException {
        try (VirgilStreamCipher cipher = new VirgilStreamCipher();
                VirgilDataSource dataSource = new VirgilStreamDataSource(inputStream);
                VirgilDataSink dataSink = new VirgilStreamDataSink(outputStream)) {

            cipher.addKeyRecipient(recipient.getRecipientId(), recipient.getValue());

            cipher.encrypt(dataSource, dataSink, true);
        } catch (IOException e) {
            throw new EncryptionException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#encrypt(java.io.InputStream, java.io.OutputStream,
     * com.virgilsecurity.sdk.crypto.PublicKey[])
     */
    @Override
    public void encrypt(InputStream inputStream, OutputStream outputStream, PublicKey[] recipients)
            throws EncryptionException {
        try (VirgilStreamCipher cipher = new VirgilStreamCipher();
                VirgilDataSource dataSource = new VirgilStreamDataSource(inputStream);
                VirgilDataSink dataSink = new VirgilStreamDataSink(outputStream)) {
            for (PublicKey recipient : recipients) {
                cipher.addKeyRecipient(recipient.getRecipientId(), recipient.getValue());
            }

            cipher.encrypt(dataSource, dataSink, true);
        } catch (IOException e) {
            throw new EncryptionException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#exportPrivateKey(com.virgilsecurity. sdk.crypto.PrivateKey)
     */
    @Override
    public byte[] exportPrivateKey(PrivateKey privateKey) {
        return exportPrivateKey(privateKey, null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#exportPrivateKey(com.virgilsecurity. sdk.crypto.PrivateKey,
     * java.lang.String)
     */
    @Override
    public byte[] exportPrivateKey(PrivateKey privateKey, String password) {
        if (password == null) {
            return VirgilKeyPair.privateKeyToDER(privateKey.getValue());
        }
        byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedKey = VirgilKeyPair.encryptPrivateKey(privateKey.getValue(), passwordBytes);

        return VirgilKeyPair.privateKeyToDER(encryptedKey, passwordBytes);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#exportPublicKey(com.virgilsecurity. sdk.crypto.PublicKey)
     */
    @Override
    public byte[] exportPublicKey(PublicKey publicKey) {
        return VirgilKeyPair.publicKeyToDER(publicKey.getValue());
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#extractPublicKey(com.virgilsecurity. sdk.crypto.PrivateKey)
     */
    @Override
    public PublicKey extractPublicKey(PrivateKey privateKey) {
        byte[] publicKeyData = VirgilKeyPair.extractPublicKey(privateKey.getValue(), new byte[0]);

        byte[] receiverId = privateKey.getRecipientId();
        byte[] value = VirgilKeyPair.publicKeyToDER(publicKeyData);

        return new VirgilPublicKey(receiverId, value);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#generateKeys()
     */
    @Override
    public KeyPair generateKeys() {
        return generateKeys(this.defaultKeyPairType);
    }

    /**
     * Generate key pair by type.
     * 
     * @param keysType
     *            the key type.
     * @return generated key pair.
     */
    public KeyPair generateKeys(KeysType keysType) {
        VirgilKeyPair keyPair = VirgilKeyPair.generate(toVirgilKeyPairType(keysType));

        byte[] keyPairId = this.computePublicKeyHash(keyPair.publicKey());

        PublicKey publicKey = new VirgilPublicKey(keyPairId, VirgilKeyPair.publicKeyToDER(keyPair.publicKey()));
        PrivateKey privateKey = new VirgilPrivateKey(keyPairId, VirgilKeyPair.privateKeyToDER(keyPair.privateKey()));

        return new KeyPair(publicKey, privateKey);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#importPrivateKey(byte[])
     */
    @Override
    public PrivateKey importPrivateKey(byte[] privateKey) throws CryptoException {
        return importPrivateKey(privateKey, null);
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#importPrivateKey(byte[], java.lang.String)
     */
    @Override
    public PrivateKey importPrivateKey(byte[] keyData, String password) throws CryptoException {
        if (keyData == null) {
            throw new NullArgumentException("keyData");
        }

        try {
            byte[] privateKeyBytes;
            if (password == null) {
                privateKeyBytes = VirgilKeyPair.privateKeyToDER(keyData);
            } else {
                privateKeyBytes = VirgilKeyPair.decryptPrivateKey(keyData, password.getBytes(StandardCharsets.UTF_8));
            }

            byte[] publicKey = VirgilKeyPair.extractPublicKey(privateKeyBytes, new byte[] {});

            byte[] receiverId = computePublicKeyHash(publicKey);
            byte[] value = VirgilKeyPair.privateKeyToDER(privateKeyBytes);
            PrivateKey privateKey = new VirgilPrivateKey(receiverId, value);

            return privateKey;
        } catch (Exception e) {
            throw new CryptoException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#importPublicKey(byte[])
     */
    @Override
    public PublicKey importPublicKey(byte[] publicKey) {
        byte[] receiverId = computePublicKeyHash(publicKey);
        byte[] value = VirgilKeyPair.publicKeyToDER(publicKey);

        return new VirgilPublicKey(receiverId, value);
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

        try (VirgilSigner signer = new VirgilSigner()) {
            byte[] signature = signer.sign(data, privateKey.getValue());
            return signature;
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

        try (VirgilStreamSigner signer = new VirgilStreamSigner();
                VirgilDataSource dataSource = new VirgilStreamDataSource(inputStream)) {
            byte[] signature = signer.sign(dataSource, privateKey.getValue());
            return signature;
        } catch (IOException e) {
            throw new SigningException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#signThenEncrypt(byte[], com.virgilsecurity.sdk.crypto.PrivateKey,
     * com.virgilsecurity.sdk.crypto.PublicKey)
     */
    @Override
    public byte[] signThenEncrypt(byte[] data, PrivateKey privateKey, PublicKey recipient) {
        return signThenEncrypt(data, privateKey, new PublicKey[] { recipient });
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#signThenEncrypt(byte[], com.virgilsecurity.sdk.crypto.PrivateKey,
     * com.virgilsecurity.sdk.crypto.PublicKey[])
     */
    @Override
    public byte[] signThenEncrypt(byte[] data, PrivateKey privateKey, PublicKey[] recipients) {
        try (VirgilSigner signer = new VirgilSigner(); VirgilCipher cipher = new VirgilCipher()) {

            byte[] signature = signer.sign(data, privateKey.getValue());

            VirgilCustomParams customData = cipher.customParams();
            customData.setData(CUSTOM_PARAM_SIGNATURE, signature);

            for (PublicKey publicKey : recipients) {
                cipher.addKeyRecipient(publicKey.getRecipientId(), publicKey.getValue());
            }
            return cipher.encrypt(data, true);

        } catch (Exception e) {
            throw new CryptoException(e.getMessage());
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#verify(byte[], byte[], com.virgilsecurity.sdk.crypto.PublicKey)
     */
    @Override
    public boolean verify(byte[] data, byte[] signature, PublicKey signer) {
        if (data == null) {
            throw new NullArgumentException("data");
        }
        if (signature == null) {
            throw new NullArgumentException("signature");
        }
        if (signer == null) {
            throw new NullArgumentException("signer");
        }

        try (VirgilSigner virgilSigner = new VirgilSigner()) {
            boolean valid = virgilSigner.verify(data, signature, signer.getValue());
            return valid;
        } catch (Exception e) {
            throw new VerificationException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#verify(java.io.InputStream, byte[],
     * com.virgilsecurity.sdk.crypto.PublicKey)
     */
    @Override
    public boolean verify(InputStream inputStream, byte[] signature, PublicKey signer) {
        if (inputStream == null) {
            throw new NullArgumentException("inputStream");
        }
        if (signature == null) {
            throw new NullArgumentException("signature");
        }
        if (signer == null) {
            throw new NullArgumentException("signer");
        }

        try (VirgilStreamSigner virgilSigner = new VirgilStreamSigner();
                VirgilDataSource dataSource = new VirgilStreamDataSource(inputStream)) {
            boolean valid = virgilSigner.verify(dataSource, signature, signer.getValue());
            return valid;
        } catch (Exception e) {
            throw new VerificationException(e);
        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.virgilsecurity.sdk.crypto.Crypto#getPrivateKey(java.lang.String)
     */
    @Override
    public PrivateKey getPrivateKey(String privateKeyId) {
        throw new MethodNotImplementedException();
    }
}
