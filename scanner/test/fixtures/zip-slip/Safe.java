import java.io.File;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

public class Safe {
    public void extract(ZipInputStream zis, File outDir) throws Exception {
        ZipEntry entry;
        String outCanonical = outDir.getCanonicalPath();
        while ((entry = zis.getNextEntry()) != null) {
            File out = new File(outDir, entry.getName());
            String canonical = out.getCanonicalPath();
            if (!canonical.startsWith(outCanonical + File.separator)) {
                throw new SecurityException("zip slip: " + entry.getName());
            }
        }
    }
}
