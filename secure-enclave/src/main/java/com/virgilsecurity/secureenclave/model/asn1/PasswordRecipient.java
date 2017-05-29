package com.virgilsecurity.secureenclave.model.asn1;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cms.PasswordRecipientInfo;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.EncryptionScheme;
import org.bouncycastle.asn1.pkcs.KeyDerivationFunc;
import org.bouncycastle.asn1.pkcs.PBES2Parameters;
import org.bouncycastle.asn1.pkcs.PBKDF2Params;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

import com.virgilsecurity.secureenclave.exceptions.ASN1Exception;

/**
 * Created by Andrii Iakovenko.
 */

public class PasswordRecipient implements ASN1Encodable {

    private byte[] kdfIV;
    private byte[] keyIV;
    private int iterations;
    private byte[] encryptedKey;

    public PasswordRecipient(byte[] kdfIv, int iterations, byte[] keyIv, byte[] encryptedKey) {
        this.kdfIV = kdfIv;
        this.iterations = iterations;
        this.keyIV = keyIv;
        this.encryptedKey = encryptedKey;
    }

    public PasswordRecipient(ASN1TaggedObject tag) {
        PasswordRecipientInfo recepient = PasswordRecipientInfo.getInstance(tag, true);
        if (recepient.getVersion().getValue().intValue() != 0) {
            throw new ASN1Exception("Unsupported recipient version");
        }
        if (!PKCSObjectIdentifiers.id_PBES2.getId()
                .equals(recepient.getKeyEncryptionAlgorithm().getAlgorithm().getId())) {
            throw new ASN1Exception("Unsupported algorithm");
        }

        PBES2Parameters paramz = PBES2Parameters.getInstance(recepient.getKeyEncryptionAlgorithm().getParameters());
        if (!NISTObjectIdentifiers.id_aes256_CBC.getId().equals(paramz.getEncryptionScheme().getAlgorithm().getId())) {
            throw new ASN1Exception("Unsupported algorithm");
        }
        if (!PKCSObjectIdentifiers.id_PBKDF2.getId().equals(paramz.getKeyDerivationFunc().getAlgorithm().getId())) {
            throw new ASN1Exception("Unsupported algorithm");
        }

        PBKDF2Params kdfParams = (PBKDF2Params) paramz.getKeyDerivationFunc().getParameters();
        if (!PKCSObjectIdentifiers.id_hmacWithSHA384.getId().equals(kdfParams.getPrf().getAlgorithm().getId())) {
            throw new ASN1Exception("Unsupported algorithm");
        }

        this.kdfIV = kdfParams.getSalt();
        this.iterations = kdfParams.getIterationCount().intValue();
        this.keyIV = ((ASN1OctetString) paramz.getEncryptionScheme().getParameters()).getOctets();
        this.encryptedKey = recepient.getEncryptedKey().getOctets();
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
        PBKDF2Params keyDerevationParameters = new PBKDF2Params(kdfIV, iterations,
                new AlgorithmIdentifier(PKCSObjectIdentifiers.id_hmacWithSHA384));
        KeyDerivationFunc func = new KeyDerivationFunc(PKCSObjectIdentifiers.id_PBKDF2, keyDerevationParameters);
        EncryptionScheme scheme = new EncryptionScheme(NISTObjectIdentifiers.id_aes256_CBC, new DEROctetString(keyIV));
        PBES2Parameters keyEncryptionParameters = new PBES2Parameters(func, scheme);
        AlgorithmIdentifier keyEncryptionAlgorithm = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_PBES2,
                keyEncryptionParameters);
        PasswordRecipientInfo info = new PasswordRecipientInfo(keyEncryptionAlgorithm,
                new DEROctetString(encryptedKey));
        return new DERTaggedObject(true, 3, info);
    }

    public static PasswordRecipient getInstance(Object obj) {
        if (obj == null) {
            return null;
        }
        if (obj instanceof PasswordRecipient) {
            return (PasswordRecipient) obj;
        }
        return new PasswordRecipient(ASN1TaggedObject.getInstance(obj));
    }

}
