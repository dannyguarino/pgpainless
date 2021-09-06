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
package investigations;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;
import org.pgpainless.PGPainless;
import org.pgpainless.decryption_verification.ConsumerOptions;
import org.pgpainless.decryption_verification.DecryptionStream;
import org.pgpainless.util.Passphrase;

public class WrongPassphraseSymmetricEncryptionTest {

    public static void main(String[] args) throws PGPException, IOException {
        investigateSymmetricEncryptionWrongPassphrase();
    }

    public static void investigateSymmetricEncryptionWrongPassphrase() throws PGPException, IOException {
        // See https://github.com/pgpainless/pgpainless/issues/174
        String msg = "-----BEGIN PGP MESSAGE-----\n" +
                "Version: FlowCrypt 7.5.9 Gmail Encryption\n" +
                "Comment: Seamlessly send and receive encrypted email\n" +
                "\n" +
                "wcFMAzBfgamu0SA1ARAAsVO7mCvul8NuZL3FhjAtGMvKOwx74lcr6XX2n8AP\n" +
                "E9TxNJOGuS8HshcI2kxap3PKusS0ZT40wnHc095PdqVRSH+PJ/69DQb84GSa\n" +
                "VmOFH4bV/JBgiC9t+4kvNQL/epxrTajPMG0l8vNwRGbsuB70aMlvMgfHKiC5\n" +
                "N8bcf1p7TPnMInfcv/tQH35MnjyPi0xVjN2NOXUNQacyEHUfhSjWm049qWP/\n" +
                "mvoZDWdWaW4qU7CWkBSm+vl4o6k6IHiRYIKoG4OYAwhrNSNA4vhcjZc/ABI6\n" +
                "aCtsD8+0Ts+mcNDbIdfNnLxT1yqhv46CEfFMyDdZ2BkYJkasECkwCKRtoMBN\n" +
                "+RcPB28a+OQH/Sv2g/NCzmpQe9dZBWWRyVv1HbOqxE7LH2/IHolDg+GrL1ut\n" +
                "j1T0bKvf//1o/WHwRHfes05dD4J5l+bDVykS9gmdeAUOyQPGw+rucSyPDwXC\n" +
                "FbngRropLlCiGSu9L08uxquLIq80f5HUML5xM3E9M2/v9mt/SnSjcwU47zPs\n" +
                "5T91q9AS8eiGS4kBzmF1NGosDX3s1CC1Vw8QjcN45zcIMgXxEQl5fDAD+nLY\n" +
                "49+VanZtcJo5AFlBczVFhDR2HIeGyaau3Kxcxa6CsmGIFjoM2RS/FkbLqKKY\n" +
                "leYGJYTZKiRSTTOhSZWgwnn6Pk4hewEdqhE4PAJxHTTDLgQJAwjuV5FCYxZT\n" +
                "4eDKWmMYMyGgMlOZ1/zFS7RQTvA35f2JIzSqO41EgX1ga6bSwtIBspb22z2+\n" +
                "ngCjl3FSWWFeKDgmq8DBIe4qGsQqVTvVXR4V44xiEh651nQPY3jMmAysByYn\n" +
                "JxKWo6Lwew3Z+IHK7AtK+i5asqNGluRuqIY+QgdVRbdJl678Lzo2ImtPjnaN\n" +
                "Wbz4xmk+lJVuyTxiK8hnEVZUPiYogniQ6ZgzTiKjkDiL7OjdxVwm/ZAnoHNv\n" +
                "W6e994A0g3PQ6k6Lon/pd0aYkfMBpo8CXWq+0CRX9Uqux/FziZ9kAnPlS56o\n" +
                "XQWJISz/F5ZlbcMTjzfBX83FY/G/hTiuu0bo0sBhOYKKeo6+thmbPiGDjIuG\n" +
                "hTnw4avIimw1Qqavj08mq0wbfPEQ9DakTfc6IUcqVKkyceBV6k95D9g8EfYc\n" +
                "mSXxlHwR/KLZKE50dUfFYOHv9FtrbFYO9wkTcddT6N5Y/RxfaOqEhNQWsrFO\n" +
                "BlXfhezebmGzqUc/qFbnJYWoIAicP8hAs+0gOTKVNafyMuD7Q2ruh2/41h/i\n" +
                "Iboa0EGJ4eNNSIAvJZ6ehDnTbPLp/9YYIrBoIGLZYNXyeF7bCllwnNdV6MhC\n" +
                "fhsU+ekP2Dr0dk7WdCAOLmeLoPzZnTHMUeaqRFYSM2dqVt35mMO7beDrCfnW\n" +
                "Q2wW+lSaNMyHHs4ao7PkBIcr92VJMCCiFuQ7SOFsGSGMgOeoIWmQxbUhuqcS\n" +
                "RUhoEspQRhQ/Ly4AlEdYRIOvHclyi8yAVyJE3xxInIfBHxdkon3h6qS5iRyD\n" +
                "WrVhBuXMir9bHqqUym/N7OVmDa47cf7/DNEK0SEFRRWIQh+6KmpDk2Xe5uL+\n" +
                "gTzcCID3/oEcmq5t3aOKFA8PVZ9qy9EKLzSVL/mHxrzBHFamo+5Vrq/+GHC4\n" +
                "bTZkMSGiJ6JL4qsR/Sdzk8hmNY+7JNx72m9YO9X8wQuFzlLrQvdICngOUBlG\n" +
                "2wo8QyggQyOeNdGF1Ys7skolmr80WfKr7We5aOEYn+zRaTM6k3f843LJWhNG\n" +
                "jkZgvkrYlQAF8e5V09Yr8Vx3YF6zMJyt4c7VGIfaxv25J6xNYbH/bRGY3Stf\n" +
                "rUHGK+rXNCMK8uobFqq0iTOorh3BXgYsM7eN/xWQyxDS8un75M2j8p+cAsyf\n" +
                "HXN3SDW8JAr9xyoj5iZpBPf7+Nht9p5e3LfzjoXa6H2Ls+V8cCZiO+bmKutL\n" +
                "MAbht0v3nw56jNgUL8QsLtUwdCgDuNDP2IL9JO239o2t0gBOlfapvcjxMGPe\n" +
                "coIlduJiUw==\n" +
                "=CRev\n" +
                "-----END PGP MESSAGE-----";

        DecryptionStream decryptionStream = PGPainless.decryptAndOrVerify()
                .onInputStream(new ByteArrayInputStream(msg.getBytes(StandardCharsets.UTF_8)))
                .withOptions(new ConsumerOptions()
                        .addDecryptionPassphrase(Passphrase.fromPassword("wrong pwd")));

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        Streams.pipeAll(decryptionStream, outputStream);
        decryptionStream.close();
    }
}
