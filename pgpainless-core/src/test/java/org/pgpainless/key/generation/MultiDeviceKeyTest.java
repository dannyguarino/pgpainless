/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.pgpainless.key.generation;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.algorithm.DocumentSignatureType;
import org.pgpainless.algorithm.KeyFlag;
import org.pgpainless.encryption_signing.EncryptionOptions;
import org.pgpainless.encryption_signing.EncryptionStream;
import org.pgpainless.encryption_signing.ProducerOptions;
import org.pgpainless.encryption_signing.SigningOptions;
import org.pgpainless.key.generation.type.KeyType;
import org.pgpainless.key.generation.type.eddsa.EdDSACurve;
import org.pgpainless.key.generation.type.xdh.XDHSpec;
import org.pgpainless.key.protection.SecretKeyRingProtector;

public class MultiDeviceKeyTest {

    private static PGPSecretKeyRing secretKeys;
    private static PGPPublicKeyRing certificate;

    @BeforeAll
    public static void prepare() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        secretKeys = generateMultiDeviceKey();
        certificate = PGPainless.extractCertificate(secretKeys);
    }

    @Test
    public void encryptForMultiDeviceKey() throws PGPException, IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        EncryptionStream encryptionStream = PGPainless.encryptAndOrSign()
                .onOutputStream(out)
                .withOptions(ProducerOptions.signAndEncrypt(
                        EncryptionOptions.encryptCommunications()
                                .addRecipient(certificate),
                        SigningOptions.get()
                                .addInlineSignature(SecretKeyRingProtector.unprotectedKeys(), secretKeys, DocumentSignatureType.BINARY_DOCUMENT)
                ).setAsciiArmor(true));

        Streams.pipeAll(new ByteArrayInputStream("Hello, World!\n".getBytes(StandardCharsets.UTF_8)), encryptionStream);
        encryptionStream.close();

        System.out.println(out);
    }

    private static PGPSecretKeyRing generateMultiDeviceKey() throws PGPException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException {
        PGPSecretKeyRing parent = PGPainless.generateKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.CERTIFY_OTHER))
                .addUserId("Parent")
                .build();

        PGPSecretKeyRing child1 = PGPainless.generateKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.CERTIFY_OTHER))
                .addSubkey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.SIGN_DATA))
                .addSubkey(KeySpec.getBuilder(KeyType.XDH(XDHSpec._X25519), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE))
                .addUserId("Child1")
                .build();

        PGPSecretKeyRing child2 = PGPainless.generateKeyRing()
                .setPrimaryKey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.CERTIFY_OTHER))
                .addSubkey(KeySpec.getBuilder(KeyType.EDDSA(EdDSACurve._Ed25519), KeyFlag.SIGN_DATA))
                .addSubkey(KeySpec.getBuilder(KeyType.XDH(XDHSpec._X25519), KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE))
                .addUserId("Child2")
                .build();

        SecretKeyRingProtector protector = SecretKeyRingProtector.unprotectedKeys();

        PGPSignatureSubpacketGenerator subpacketGenerator = new PGPSignatureSubpacketGenerator();
        subpacketGenerator.setKeyFlags(true, KeyFlag.toBitmask(KeyFlag.CERTIFY_OTHER));

        PGPSecretKeyRing combined = PGPainless.modifyKeyRing(parent)
                .addSubKey(child1.getSecretKey(), subpacketGenerator.generate(), null, protector, protector)
                .addSubKey(child2.getSecretKey(), subpacketGenerator.generate(), null, protector, protector)
                .done();

        List<PGPSecretKey> keys = new ArrayList<>();
        Iterator<PGPSecretKey> combinedKeys = combined.getSecretKeys();
        while (combinedKeys.hasNext()) {
            keys.add(combinedKeys.next());
        }

        Iterator<PGPSecretKey> child1Subs = child1.getSecretKeys();
        child1Subs.next();
        while (child1Subs.hasNext()) {
            keys.add(child1Subs.next());
        }

        Iterator<PGPSecretKey> child2Subs = child2.getSecretKeys();
        child2Subs.next();
        while (child2Subs.hasNext()) {
            keys.add(child2Subs.next());
        }

        combined = new PGPSecretKeyRing(keys);

        return combined;
    }
}
