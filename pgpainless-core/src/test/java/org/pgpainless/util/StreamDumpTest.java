package org.pgpainless.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;
import org.pgpainless.algorithm.SymmetricKeyAlgorithm;

public class StreamDumpTest {

    @Test
    public void test() throws IOException, PGPException {
        String encryptedMessage = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "wV4Di9iOlMDSAzMSAQdAu/2VmD0uZASFHqAD0IVNq7C8rdsJ+ZQd2nQsuBilygUw\n" +
                "9bK+bOzU6ksTZgKgdAjO8zpvM+N0B3L0TtiwLr5rj0rPkCyVLdACnBpWOCZCMpsK\n" +
                "0j4B4um24+oCDHtxRu1e1IvsboBtGN9ElxidGAiUdPJ3L0QrNVgzdmVTwuywtIHW\n" +
                "r66Eaq8vCTmJpcsy0BYTiQ==\n" +
                "=FY/Q\n" +
                "-----END PGP MESSAGE-----\n";
        PGPSessionKey sessionKey = new PGPSessionKey(SymmetricKeyAlgorithm.AES_256.getAlgorithmId(), Hex.decode("920B1779565C8DF4DD9DB46966CDF2B51BC882C241DE8EF437CADEC711E7EB04"));

        String signedMessage = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "xA0DAAgB0D9vhlIm/osBxA0DAAoWCTXiD9yZ2YYByxRiAAAAAABIZWxsbywgd29y\n" +
                "bGQhCsJ1BAAWCgAnBYJcdpUyFiEEjeZMrRdY/BlFYM9ZCTXiD9yZ2YYJEAk14g/c\n" +
                "mdmGAAC5AgD/U/FD8PPqqABrkdg9bV4aToP6YENgXGq8M7SIvTaznl0BAM1KdOKs\n" +
                "UWPQgh5AJp3kOUzSO7v+brfw03O1wQaOmgsHwsBzBAABCAAnBYJdkKU/FiEEPoh3\n" +
                "yHcnRpKXUYn10D9vhlIm/osJENA/b4ZSJv6LAAAQ1Qf/bC4uL61DQrR0s+3n7By8\n" +
                "Rp0cfppfR94NK9GUtCcL03Ci78qimpjcZja+r03xTj4r3TGASRngaYD0cOU+erF9\n" +
                "DO3PPGZKxajOqtFXoQKdQnUhaRnU2CMfL+voRzH7kFssvcHzy7JoeFDLxadt8yym\n" +
                "Hm3vN+oDB3b8uWVEzaVMn71cbjJzlsLBaLclSlE/Nj36x9TeunnHhZJ7BFmkTaBd\n" +
                "W5kdBtqIV6Mii+xiYjrtrkFzYkEDNz6hK2so8SjpaGck2tSiBSrybf0/CLWwb/+e\n" +
                "i6yLPi6Afbxz+5Yp4jjxNkUdjeQFNFExix0DUPVowhZQN9hwZvJXmfUzi71+BB6N\n" +
                "uA==\n" +
                "=BDwS\n" +
                "-----END PGP MESSAGE-----\n";

        String compressedSignedMessage = "-----BEGIN PGP MESSAGE-----\n" +
                "\n" +
                "owGbwMvMwCH2sPOSUOzzWymMp0WSGGK6InU9UnNy8nUUyvOLclIUuTpKWRjEOBhk\n" +
                "xRRZ8jZHv1c9Zfp0SurkSJguViaQFgYuTgGYSJ09w/8M9xn6J9em8Bvs3rHgYd+G\n" +
                "z519Zy++FFuYsPHwz8KmXNliRoaNP2zq+A5kp7MJWjc2JrdXW8y+GTd9So2lDcMq\n" +
                "h3UsTFwA\n" +
                "=56Gw\n" +
                "-----END PGP MESSAGE-----";

        ArmoredInputStream inputStream = new ArmoredInputStream(new ByteArrayInputStream(encryptedMessage.getBytes(StandardCharsets.UTF_8)));

        StreamDumper.dump(inputStream, sessionKey);
    }
}
