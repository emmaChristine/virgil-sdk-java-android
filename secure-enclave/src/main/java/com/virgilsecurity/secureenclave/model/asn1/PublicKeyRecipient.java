package com.virgilsecurity.secureenclave.model.asn1;

import android.security.keystore.KeyProperties;

import com.virgilsecurity.secureenclave.exceptions.ASN1Exception;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;

import java.io.IOException;

/**
 * Created by Andrii Iakovenko.
 */

public class PublicKeyRecipient implements ASN1Encodable {

    private static final ASN1ObjectIdentifier KDF2 = new ASN1ObjectIdentifier("1.0.18033.2.5.2");

    private byte[] encryptedSymmetricKey;
    private byte[] ephemeralPublicKey;
    private byte[] id;
    private byte[] tag;
    private byte[] iv;
    private String algorithm;

    public PublicKeyRecipient(String algorithm, byte[] id, byte[] encryptedSymmetricKey) {
        if (KeyProperties.KEY_ALGORITHM_RSA.equalsIgnoreCase(algorithm)) {
            this.algorithm = PKCSObjectIdentifiers.rsaEncryption.getId();
        } else if (KeyProperties.KEY_ALGORITHM_EC.equalsIgnoreCase(algorithm)) {
            // TODO Fix key recipient for RSA key
            this.algorithm = PKCSObjectIdentifiers.rsaEncryption.getId();
        } else {
            throw new ASN1Exception("Unsupported algorithm");
        }
        this.id = id;
        this.encryptedSymmetricKey = encryptedSymmetricKey;
    }

    public PublicKeyRecipient(ASN1Sequence asn1Sequence) {
        KeyTransRecipientInfo ktri = KeyTransRecipientInfo.getInstance(asn1Sequence);
        if (ktri.getVersion().getValue().intValue() != 2) {
            throw new ASN1Exception("Unsupported public key recipient version");
        }

        this.algorithm = ktri.getKeyEncryptionAlgorithm().getAlgorithm().getId();
        if (PKCSObjectIdentifiers.rsaEncryption.getId().equals(algorithm)) {
            // RSA key
            this.encryptedSymmetricKey = ktri.getEncryptedKey().getOctets();
        } else if (X9ObjectIdentifiers.id_ecPublicKey.getId().equals(algorithm)) {
            // EC key
            if (true) throw new ASN1Exception("Unsupported algorithm");
            try {
                ASN1Sequence seq = (ASN1Sequence) ASN1Sequence.fromByteArray(ktri.getEncryptedKey().getOctets());
                ASN1Integer v = ASN1Integer.getInstance(seq.getObjectAt(0));
                if (v.getValue().intValue() != 0) {
                    throw new ASN1Exception("Unsupported algorithm version");
                }

                ASN1Sequence seqEphemeralPublicKey = (ASN1Sequence) seq.getObjectAt(1);

                if (! X9ObjectIdentifiers.id_ecPublicKey.getId().equals(AlgorithmIdentifier.getInstance(seqEphemeralPublicKey.getObjectAt(0)).getAlgorithm().getId())) {
                    throw new ASN1Exception("Unsupported algorithm");
                }

                this.ephemeralPublicKey = seqEphemeralPublicKey.getEncoded();

                AlgorithmIdentifier algoKdf = AlgorithmIdentifier.getInstance(seq.getObjectAt(2));
                if (! KDF2.getId().equals(algoKdf.getAlgorithm().getId())){
                    throw new ASN1Exception("Unsupported algorithm");
                }
                if (! NISTObjectIdentifiers.id_sha384.getId().equals(ASN1ObjectIdentifier.getInstance(ASN1Sequence.getInstance(algoKdf.getParameters()).getObjectAt(0)).getId())) {
                    throw new ASN1Exception("Unsupported algorithm");
                }

                ASN1Sequence tag = (ASN1Sequence) ASN1Sequence.getInstance(seq.getObjectAt(3));
                if (! NISTObjectIdentifiers.id_sha384.getId().equals(AlgorithmIdentifier.getInstance(tag.getObjectAt(0)).getAlgorithm().getId())) {
                    throw new ASN1Exception("Unsupported algorithm");
                }
                this.tag = ((ASN1OctetString) tag.getObjectAt(1)).getOctets();

                ASN1Sequence symetricKey = ASN1Sequence.getInstance(seq.getObjectAt(4));
                EncryptionScheme scheme = EncryptionScheme.getInstance(symetricKey.getObjectAt(0));
                if (! NISTObjectIdentifiers.id_aes256_CBC.getId().equals(scheme.getAlgorithm().getId())) {
                    throw new ASN1Exception("Unsupported algorithm");
                }
                this.iv = ((ASN1OctetString) scheme.getParameters()).getOctets();

                this.encryptedSymmetricKey = ASN1OctetString.getInstance(symetricKey.getObjectAt(1)).getOctets();
            } catch (IOException e) {
                throw new ASN1Exception("Wrong symmetric key");
            }
        } else {
            throw new ASN1Exception("Unsupported algorithm");
        }

        this.id = ((DEROctetString) ktri.getRecipientIdentifier().getId()).getOctets();
    }

    public static PublicKeyRecipient getInstance(Object obj) {
        if (obj == null) {
            return null;
        }
        if (obj instanceof PublicKeyRecipient) {
            return (PublicKeyRecipient) obj;
        }
        return new PublicKeyRecipient(ASN1Sequence.getInstance(obj));
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        RecipientIdentifier rid = new RecipientIdentifier(new DERTaggedObject(true, 0, new DEROctetString(id)));
        ASN1ObjectIdentifier alg = new ASN1ObjectIdentifier(this.algorithm);
        AlgorithmIdentifier algorithm = new AlgorithmIdentifier(alg);

        KeyTransRecipientInfo info = new KeyTransRecipientInfo(rid, algorithm,
                new DEROctetString(encryptedSymmetricKey));
        return info.toASN1Primitive();
    }

    public byte[] getEncryptedSymmetricKey() {
        return encryptedSymmetricKey;
    }

    public byte[] getId() {
        return id;
    }

    public byte[] getEphemeralPublicKey() {
        return ephemeralPublicKey;
    }

    public byte[] getTag() {
        return tag;
    }

    public byte[] getIv() {
        return iv;
    }

    public String getAlgorithm() {
        return algorithm;
    }
}
