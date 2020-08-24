/*
 * Copyright 2018 Paul Schaub.
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
package org.pgpainless.decryption_verification;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Set;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.pgpainless.key.OpenPgpV4Fingerprint;
import org.pgpainless.key.protection.SecretKeyRingProtector;

public interface DecryptionBuilderInterface {

    DecryptWith onInputStream(InputStream inputStream);

    interface DecryptWith {

        Verify decryptWith(@Nonnull SecretKeyRingProtector decryptor, @Nonnull PGPSecretKeyRingCollection secretKeyRings);

        Verify doNotDecrypt();

    }

    interface Verify extends VerifyWith {

        VerifyWith verifyDetachedSignature(InputStream inputStream) throws IOException, PGPException;

        VerifyWith verifyDetachedSignatures(List<PGPSignature> signatures);

        Build doNotVerify();
    }

    interface VerifyWith {

        HandleMissingPublicKeys verifyWith(@Nonnull PGPPublicKeyRingCollection publicKeyRings);

        HandleMissingPublicKeys verifyWith(@Nonnull Set<OpenPgpV4Fingerprint> trustedFingerprints, @Nonnull PGPPublicKeyRingCollection publicKeyRings);

        HandleMissingPublicKeys verifyWith(@Nonnull Set<PGPPublicKeyRing> publicKeyRings);


    }

    interface HandleMissingPublicKeys {

        Build handleMissingPublicKeysWith(@Nonnull MissingPublicKeyCallback callback);

        Build ignoreMissingPublicKeys();
    }

    interface Build {

        DecryptionStream build() throws IOException, PGPException;

    }

}
