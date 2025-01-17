// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.decryption_verification;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.cleartext_signatures.InMemoryMultiPassStrategy;

public class VerifyDetachedSignatureTest {

    @Test
    public void verify() throws PGPException, IOException {
        String signedContent = "Content-Type: multipart/mixed; boundary=\"OSR6TONWKJD9dgyc2XH5AQPNnAs7pdg1t\"\n" +
                "\n" +
                "--OSR6TONWKJD9dgyc2XH5AQPNnAs7pdg1t\n" +
                "Content-Type: text/plain; charset=utf-8\n" +
                "Content-Transfer-Encoding: quoted-printable\n" +
                "Content-Language: en-US\n" +
                "\n" +
                "NOT encrypted + signed(detached)\n" +
                "\n" +
                "\n" +
                "\n" +
                "--OSR6TONWKJD9dgyc2XH5AQPNnAs7pdg1t--\n";
        String signature = "-----BEGIN PGP SIGNATURE-----\n" +
                "\n" +
                "iHUEARYIAB0WIQTBZCjWAcs5N4nPYdTDIInNavjWzgUCYgKPzAAKCRDDIInNavjW\n" +
                "zmdoAP0TdFt1OWqosHhXxt2hNYqZQMc6bgQRpJNL029nRyzkPAD/SoYJ4T+aYEhw\n" +
                "11qrbXloqkr0G3QaA6/zk31RPMI/bgI=\n" +
                "=o5Ze\n" +
                "-----END PGP SIGNATURE-----\n";
        String pubkey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n" +
                "Version: PGPainless\n" +
                "\n" +
                "mDMEYIucWBYJKwYBBAHaRw8BAQdAew+8mzMWyf3+Pfy49qa60uKV6e5os7de4TdZ\n" +
                "ceAWUq+0F2RlbmJvbmQ3QGZsb3djcnlwdC50ZXN0iHgEExYKACAFAmCLnFgCGwMF\n" +
                "FgIDAQAECwkIBwUVCgkICwIeAQIZAQAKCRDDIInNavjWzm3JAQCgFgCEyD58iEa/\n" +
                "Rw/DYNoQNoZC1lhw1bxBiOcIbtkdBgEAsDFZu3TBavOMKI7KW+vfMBHtRVbkMNpv\n" +
                "unaAldoabgO4OARgi5xYEgorBgEEAZdVAQUBAQdAB1/Mrq5JGYim4KqGTSK4OESQ\n" +
                "UwPgK56q0yrkiU9WgyYDAQgHiHUEGBYKAB0FAmCLnFgCGwwFFgIDAQAECwkIBwUV\n" +
                "CgkICwIeAQAKCRDDIInNavjWzjMgAQCU+R1fItqdY6lt9jXUqipmXuqVaEFPwNA8\n" +
                "YJ1rIwDwVQEAyUc8162KWzA2iQB5akwLwNr/pLDDtOWwhLUkrBb3mAc=\n" +
                "=pXF6\n" +
                "-----END PGP PUBLIC KEY BLOCK-----\n";


        DecryptionStream verifier = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(signedContent.getBytes(StandardCharsets.UTF_8)))
                .withOptions(
                        new ConsumerOptions()
                                .addVerificationOfDetachedSignatures(new ByteArrayInputStream(signature.getBytes(StandardCharsets.UTF_8)))
                                .addVerificationCerts(PGPainless.readKeyRing().keyRingCollection(pubkey, true).getPgpPublicKeyRingCollection())
                                .setMultiPassStrategy(new InMemoryMultiPassStrategy())
                );

        Streams.drain(verifier);
        verifier.close();
        OpenPgpMetadata metadata = verifier.getResult();
        assertTrue(metadata.isVerified());
    }
}
