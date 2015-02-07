import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Created by kevinbjiang on 2/7/15.
 */
public class TimeBasedOTP
{
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeyException, IOException
    {
        if (args.length != 1)
        {
            printUsage();
            System.exit(-1);
        }

        try
        {
            Path path = Paths.get(args[0]);
            byte[] secret = Files.readAllBytes(path);

            TOTPGenerator gen = new TOTPGenerator(secret);
            System.out.println(gen.generateOTP());
        }
        catch (NoSuchFileException e)
        {
            System.out.println("Could not find token file");
            System.exit(-1);
        }
    }

    private static void printUsage()
    {
        System.out.println("totp <shared secret file>");
    }
}
