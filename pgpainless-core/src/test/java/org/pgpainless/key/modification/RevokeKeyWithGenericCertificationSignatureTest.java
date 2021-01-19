/*
 * Copyright 2021 Ivan Pizhenko, Paul Schaub.
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
package org.pgpainless.key.modification;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.key.protection.UnprotectedKeysProtector;

/**
 * Test that makes sure that PGPainless can deal with keys that carry a key
 * signature of type 0x10 (generic certification).
 *
 * Originally PGPainless would only handle keys with key signature type
 * 0x13 (positive certification) and would otherwise crash when negotiating
 * algorithms, esp. when revoking a key.
 *
 * @see <a href="Github Issue">https://github.com/pgpainless/pgpainless/issues/53</a>
 */
public class RevokeKeyWithGenericCertificationSignatureTest {

    // key has key sig of type 0x10
    private static final String SAMPLE_PRIVATE_KEY =
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\n" +
                    "Version: MyApplication 1.0.0\r\n" +
                    "Comment: Some comment\r\n" +
                    "\r\n" +
                    "xVgEX6UIExYJKwYBBAHaRw8BAQdAMfHf64wPQ2LC9In5AKYU/KT1qWvI7e7a\r\n" +
                    "Xr+LWeQGUKIAAQCcB3zZlHfepQT26LIwbTDn4lvQ9LuD1fk2hK6i9FXFxxO7\r\n" +
                    "zRI8dXNlckBleGFtcGxlLmNvbT7CjwQQFgoAIAUCX6UIEwYLCQcIAwIEFQgK\r\n" +
                    "AgQWAgEAAhkBAhsDAh4BACEJEEoCtcZ3snFuFiEENY1GQZqrKQqgUAXASgK1\r\n" +
                    "xneycW6P6AEA5iXFK+fWpj0vn3xpKEuFRqvytPKFzhwd4wEvL+IGSPEBALE/\r\n" +
                    "pZdMzsDoKPENiLFpboDVNVJScwFXIleKmtNaRycFx10EX6UIExIKKwYBBAGX\r\n" +
                    "VQEFAQEHQBDdeawWVNqYkP8c/ihLEUlVpn8cQw7rmRc/sIhdAXhfAwEIBwAA\r\n" +
                    "/0Jy7IelcHDjxE3OzagEzSxNrCVw8uPHNRl8s6iP+CQYEfHCeAQYFggACQUC\r\n" +
                    "X6UIEwIbDAAhCRBKArXGd7JxbhYhBDWNRkGaqykKoFAFwEoCtcZ3snFuWp8B\r\n" +
                    "AIzRBYJSfZzlvlyyPhrbXJoYSICGNy/5x7noXjp/ByeOAQDnTbQi4XwXJrU4\r\n" +
                    "A8Nl9eyz16ZWUzEPwfWgahIG1eQDDA==\r\n" +
                    "=bk4o\r\n" +
                    "-----END PGP PRIVATE KEY BLOCK-----\r\n";

    public static class KeyPair {
        public final String pub;
        public final String priv;

        public KeyPair(byte[] pub, byte[] priv) {
            this.pub = new String(pub, StandardCharsets.UTF_8);
            this.priv = new String(pub, StandardCharsets.UTF_8);
        }
    }

    @Test
    public void test() throws IOException, PGPException {
        revokeKey(SAMPLE_PRIVATE_KEY); // would crash previously
    }

    private KeyPair revokeKey(String priv) throws IOException, PGPException {
        byte[] armoredBytes = priv.getBytes(StandardCharsets.UTF_8);
        PGPSecretKeyRing r = PGPainless.readKeyRing()
                .secretKeyRing(armoredBytes);
        PGPSecretKey secretKey = r.getSecretKey();
        // this is not ideal, but still valid usage
        PGPSecretKeyRing secretKeyRing =
                PGPainless.modifyKeyRing(new PGPSecretKeyRing(Arrays.asList(secretKey)))
                        .revoke(new UnprotectedKeysProtector()).done();

        PGPPublicKey pkr = secretKeyRing.getPublicKeys().next();
        ByteArrayOutputStream pubOutBytes = new ByteArrayOutputStream();
        try (ArmoredOutputStream pubOut = new ArmoredOutputStream(pubOutBytes)) {
            pkr.encode(pubOut);
        }
        pubOutBytes.close();

        PGPSecretKey skr = secretKeyRing.getSecretKeys().next();
        ByteArrayOutputStream secOutBytes = new ByteArrayOutputStream();
        try (ArmoredOutputStream privOut = new ArmoredOutputStream(secOutBytes)) {
            skr.encode(privOut);
        }
        secOutBytes.close();

        return new KeyPair(pubOutBytes.toByteArray(), secOutBytes.toByteArray());
    }
}

