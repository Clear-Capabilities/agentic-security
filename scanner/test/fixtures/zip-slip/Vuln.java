import java.io.File;
import java.io.FileOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class Vuln {
    public void extract(ZipInputStream zis, File outDir) throws Exception {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            File out = new File(outDir, entry.getName());
            try (FileOutputStream fos = new FileOutputStream(out)) {
                byte[] buf = new byte[4096];
                int n;
                while ((n = zis.read(buf)) > 0) fos.write(buf, 0, n);
            }
        }
    }
}
