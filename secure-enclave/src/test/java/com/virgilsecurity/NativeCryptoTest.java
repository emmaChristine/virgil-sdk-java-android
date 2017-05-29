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
package com.virgilsecurity;

/**
 * @author Andrii Iakovenko
 *
 */
public class NativeCryptoTest {
/*
    private static final String TEXT = "Lorem Ipsum is simply dummy text of the printing and typesetting industry.";
    private static final byte[] DATA = TEXT.getBytes(StandardCharsets.UTF_8);
    private String password;

    private Crypto virgilCrypto;

    private Crypto nativeCrypto;

    @Before
    public void setUp() {
        // virgilCrypto = new VirgilCrypto();
        virgilCrypto = new VirgilCrypto(KeysType.RSA_2048);
        nativeCrypto = new NativeCrypto();
        password = UUID.randomUUID().toString();
    }

    @Test
    public void calculateFingerprint() {
        Fingerprint fingerprint = nativeCrypto.calculateFingerprint(DATA);

        assertNotNull(fingerprint);
        assertTrue(fingerprint.getValue().length > 0);
    }

    @Test
    public void calculateFingerprint_compartibility() {
        Fingerprint virgilFingerprint = virgilCrypto.calculateFingerprint(DATA);
        Fingerprint nativeFingerprint = nativeCrypto.calculateFingerprint(DATA);

        assertArrayEquals(virgilFingerprint.getValue(), nativeFingerprint.getValue());
    }

    @Test
    public void computeHash_compartibility() {
        for (HashAlgorithm algorithm : HashAlgorithm.values()) {
            byte[] virgilHash = virgilCrypto.computeHash(DATA, algorithm);
            byte[] nativeHash = nativeCrypto.computeHash(DATA, algorithm);

            assertArrayEquals(String.valueOf(algorithm), virgilHash, nativeHash);
        }
    }

    @Test
    public void generateKeys() {
        KeyPair nativeKeyPair = nativeCrypto.generateKeys();
        assertNotNull(nativeKeyPair);

        PublicKey publicKey = nativeKeyPair.getPublicKey();
        validateKey(publicKey);

        PrivateKey privateKey = nativeKeyPair.getPrivateKey();
        validateKey(privateKey);
    }

    @Test
    public void exportPrivateKey() {
        KeyPair keyPair = nativeCrypto.generateKeys();
        byte[] exportedKey = nativeCrypto.exportPrivateKey(keyPair.getPrivateKey());

        assertNotNull(exportedKey);
        assertTrue(exportedKey.length > 0);
    }

    @Test
    @Ignore
    public void exportPrivateKey_withPassword() {
        KeyPair keyPair = nativeCrypto.generateKeys();
        byte[] exportedKey = nativeCrypto.exportPrivateKey(keyPair.getPrivateKey(), password);

        assertNotNull(exportedKey);
        assertTrue(exportedKey.length > 0);
    }

    @Test
    @Ignore
    public void exportPrivateKey_compartibility() {
        KeyPair keyPair = nativeCrypto.generateKeys();
        byte[] exportedKeyNative = nativeCrypto.exportPrivateKey(keyPair.getPrivateKey());
        byte[] exportedKeyVirgil = virgilCrypto.exportPrivateKey(keyPair.getPrivateKey());

        assertArrayEquals(exportedKeyVirgil, exportedKeyNative);

        PrivateKey importedKey = virgilCrypto.importPrivateKey(exportedKeyNative);
        validateKey(importedKey);
    }

    @Test
    @Ignore
    public void exportPrivateKey_withPassword_compartibility() {
        KeyPair keyPair = nativeCrypto.generateKeys();
        byte[] exportedKeyNative = nativeCrypto.exportPrivateKey(keyPair.getPrivateKey(), password);

        PrivateKey importedKey = virgilCrypto.importPrivateKey(exportedKeyNative, password);
        validateKey(importedKey);
    }

    @Test(expected = CryptoException.class)
    @Ignore
    public void exportPrivateKey_withWrongPassword_compartibility() {
        KeyPair keyPair = nativeCrypto.generateKeys();
        byte[] exportedKeyNative = nativeCrypto.exportPrivateKey(keyPair.getPrivateKey(), password);

        virgilCrypto.importPrivateKey(exportedKeyNative, "1");
    }

    @Test
    public void exportPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyPair keyPair = nativeCrypto.generateKeys();

        PublicKey publicKey = keyPair.getPublicKey();
        byte[] exportedKey = nativeCrypto.exportPublicKey(publicKey);

        assertNotNull(exportedKey);
        assertTrue(exportedKey.length > 0);
    }

    @Test
    public void exportPublicKey_compartibility() {
        KeyPair keyPair = nativeCrypto.generateKeys();

        PublicKey publicKey = keyPair.getPublicKey();
        byte[] exportedKeyVirgil = virgilCrypto.exportPublicKey(publicKey);
        byte[] exportedKeyNative = nativeCrypto.exportPublicKey(publicKey);

        assertArrayEquals(exportedKeyVirgil, exportedKeyNative);
    }

    @Test
    public void extractPublicKey() {
        KeyPair keyPair = nativeCrypto.generateKeys();
        PublicKey publicKey = nativeCrypto.extractPublicKey(keyPair.getPrivateKey());

        validateKey(publicKey);
    }

    @Test
    @Ignore
    public void extractPublicKey_compartibility() {
        KeyPair keyPair = nativeCrypto.generateKeys();
        PublicKey publicKeyNative = nativeCrypto.extractPublicKey(keyPair.getPrivateKey());
        PublicKey publicKeyVirgil = virgilCrypto.extractPublicKey(keyPair.getPrivateKey());

        assertEquals(publicKeyVirgil.getRecipientId().length, publicKeyNative.getRecipientId().length);
        assertEquals(publicKeyVirgil.getValue().length, publicKeyNative.getValue().length);
        assertArrayEquals(publicKeyVirgil.getValue(), publicKeyNative.getValue());
    }

    @Test
    @Ignore
    public void encrypt_decrypt() {
        KeyPair nativeKeyPair = nativeCrypto.generateKeys();

        byte[] encrypted = nativeCrypto.encrypt(DATA, nativeKeyPair.getPublicKey());
        byte[] decrypted = nativeCrypto.decrypt(encrypted, nativeKeyPair.getPrivateKey());

        assertArrayEquals(DATA, decrypted);
    }

    @Test
    @Ignore
    public void encrypt_decrypt_with_nativeKeys_compartibility() {
        KeyPair nativeKeyPair = nativeCrypto.generateKeys();

        byte[] encrypted = virgilCrypto.encrypt(DATA, nativeKeyPair.getPublicKey());
        byte[] decrypted = nativeCrypto.decrypt(encrypted, nativeKeyPair.getPrivateKey());

        assertArrayEquals(DATA, decrypted);
    }

    @Test
    @Ignore
    public void encrypt_decrypt_with_virgilKeys_compartibility() {
        KeyPair virgilKeyPair = virgilCrypto.generateKeys();

        byte[] encrypted = virgilCrypto.encrypt(DATA, virgilKeyPair.getPublicKey());
        byte[] decrypted = nativeCrypto.decrypt(encrypted, virgilKeyPair.getPrivateKey());

        assertArrayEquals(DATA, decrypted);
    }

    @Test
    @Ignore
    public void sign_with_nativeKeys_compartibility() {
        // KeyPair virgilKeyPair = virgilCrypto.generateKeys();
        KeyPair virgilKeyPair = nativeCrypto.generateKeys();

        byte[] virgilSign = virgilCrypto.sign(DATA, virgilKeyPair.getPrivateKey());
        byte[] nativeSign = nativeCrypto.sign(DATA, virgilKeyPair.getPrivateKey());

        assertArrayEquals(virgilSign, nativeSign);
    }

    @Test
    public void importPrivateKey() {
        KeyPair keyPair = nativeCrypto.generateKeys();
        byte[] exportedKey = nativeCrypto.exportPrivateKey(keyPair.getPrivateKey());
        PrivateKey importedKey = nativeCrypto.importPrivateKey(exportedKey);
        validateKey(importedKey);
    }

    @Test
    public void importPrivateKey_compartibility() {
        KeyPair keyPair = virgilCrypto.generateKeys();
        byte[] exportedKey = virgilCrypto.exportPrivateKey(keyPair.getPrivateKey());
        PrivateKey importedKey = nativeCrypto.importPrivateKey(exportedKey);
        validateKey(importedKey);
    }

    private void validateKey(Key key) {
        assertNotNull(key);
        assertNotNull(key.getRecipientId());
        assertTrue(key.getRecipientId().length > 0);
        assertNotNull(key.getValue());
        assertTrue(key.getValue().length > 0);
    }

    @Test
    @Ignore
    public void xxx() {
        KeyPair keyPair = nativeCrypto.generateKeys();
        byte[] exportedKey = nativeCrypto.exportPrivateKey(keyPair.getPrivateKey());

        PrivateKey pk1 = nativeCrypto.importPrivateKey(exportedKey);
        PrivateKey pk2 = virgilCrypto.importPrivateKey(exportedKey);

        assertArrayEquals(pk1.getRecipientId(), pk2.getRecipientId());

        PublicKey puk1 = nativeCrypto.extractPublicKey(pk1);
        PublicKey puk2 = nativeCrypto.extractPublicKey(pk2);

        assertArrayEquals(puk1.getRecipientId(), puk2.getRecipientId());
        assertArrayEquals(puk1.getValue(), puk2.getValue());
    }
*/
}
