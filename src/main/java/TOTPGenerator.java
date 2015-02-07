import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by kevinbjiang on 2/7/15.
 */
public class TOTPGenerator
{
    public static final String HMAC_ALGORITHM = "HmacSHA1";
    private final SecretKeySpec keySpec;
    private final Mac mac;

    public TOTPGenerator(byte[] sharedKey) throws NoSuchAlgorithmException, InvalidKeyException
    {
        this.keySpec = new SecretKeySpec(sharedKey, HMAC_ALGORITHM);
        this.mac = Mac.getInstance(HMAC_ALGORITHM);
        this.mac.init(keySpec);
    }

    int generateOTP()
    {
        // Step 1: Generate an HMAC-SHA-1 value Let HS = HMAC-SHA-1(K,C)  // HS
        // is a 20-byte string

        //time step
        long time = (System.currentTimeMillis()/1000) / 30;
        byte[] timeBytes = ByteBuffer.allocate(8).putLong(time).array();

        //calc hmac
        mac.reset();
        byte[] hmac = mac.doFinal(timeBytes);


        // Step 2: Generate a 4-byte string (Dynamic Truncation)
        // Let Sbits = DT(HS)   //  DT, defined below,
        // returns a 31-bit string
        int offset = (hmac[hmac.length - 1] & 0xF);
        byte[] dynamicTruncationBytes = new byte[4];
        System.arraycopy(hmac, offset, dynamicTruncationBytes, 0, 4);
        dynamicTruncationBytes[0] = (byte) (dynamicTruncationBytes[0] & 0x7f);


        // Step 3: Compute an HOTP value
        // Let Snum  = StToNum(Sbits)   // Convert S to a number in
        // 0...2^{31}-1
        // Return D = Snum mod 10^Digit //  D is a number in the range
        // 0...10^{Digit}-1
        int untruncatedCode = ByteBuffer.wrap(dynamicTruncationBytes).getInt();
        int truncatedCode = untruncatedCode % 1000000;

        return truncatedCode;
    }
}
