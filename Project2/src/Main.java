/**
 * Created by Will on 2/5/2017.
 */

import java.io.BufferedReader;
import java.io.FileReader;
import java.security.MessageDigest;
import javax.xml.bind.DatatypeConverter;

public class Main
{
    public static void main(String[] args) throws Exception
    {
        recover_password("dict.txt", new String[] {
                "6F047CCAA1ED3E8E05CDE1C7EBC7D958",
                "275A5602CD91A468A0E10C226A03A39C",
                "B4BA93170358DF216E8648734AC2D539",
                "DC1C6CA00763A1821C5AF993E0B6F60A",
                "8CD9F1B962128BD3D3EDE2F5F101F4FC",
                "554532464E066ABA23AEE72B95F18BA2"
        });
    }

    public static void recover_password(String file_path, String[] hashes) throws Exception
    {
        MessageDigest hasher = MessageDigest.getInstance("MD5");
        BufferedReader reader = new BufferedReader(new FileReader(file_path));

        // Get the start time
        long start = System.currentTimeMillis();

        String line = reader.readLine();
        while (line != null)
        {
            byte[] hash = hasher.digest(line.getBytes("UTF-8"));
            String hex = DatatypeConverter.printHexBinary(hash);

            for (String target : hashes)
            {
                if (hex.equals(target))
                {
                    long end = System.currentTimeMillis();
                    System.out.print("Password for ");
                    System.out.print(hex);
                    System.out.print(" is: ");
                    System.out.println(line);
                    System.out.print("Found in: ");
                    System.out.print(end - start);
                    System.out.println(" milliseconds");
                }
            }

            line = reader.readLine();
        }
    }
}
