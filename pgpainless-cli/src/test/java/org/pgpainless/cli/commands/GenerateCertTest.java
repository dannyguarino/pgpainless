// SPDX-FileCopyrightText: 2021 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package org.pgpainless.cli.commands;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.pgpainless.cli.TestUtils.ARMOR_PRIVATE_KEY_HEADER_BYTES;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.util.Arrays;

import com.ginsberg.junit.exit.FailOnSystemExit;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.junit.jupiter.api.Test;
import org.pgpainless.PGPainless;
import org.pgpainless.cli.PGPainlessCLI;
import org.pgpainless.key.info.KeyRingInfo;

public class GenerateCertTest {

    @Test
    @FailOnSystemExit
    public void testKeyGeneration() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
        PGPainlessCLI.execute("generate-key", "--armor", "Juliet Capulet <juliet@capulet.lit>");

        PGPSecretKeyRing secretKeys = PGPainless.readKeyRing().secretKeyRing(out.toByteArray());
        KeyRingInfo info = PGPainless.inspectKeyRing(secretKeys);
        assertTrue(info.isUserIdValid("Juliet Capulet <juliet@capulet.lit>"));

        byte[] outBegin = new byte[37];
        System.arraycopy(out.toByteArray(), 0, outBegin, 0, 37);
        assertArrayEquals(outBegin, ARMOR_PRIVATE_KEY_HEADER_BYTES);
    }

    @Test
    @FailOnSystemExit
    public void testNoArmor() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out));
        PGPainlessCLI.execute("generate-key", "--no-armor", "Test <test@test.test>");

        byte[] outBegin = new byte[37];
        System.arraycopy(out.toByteArray(), 0, outBegin, 0, 37);
        assertFalse(Arrays.equals(outBegin, ARMOR_PRIVATE_KEY_HEADER_BYTES));
    }
}
