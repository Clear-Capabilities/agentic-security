package demo;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.fileupload.FileItem;
import org.apache.commons.fileupload.disk.DiskFileItemFactory;
import org.apache.commons.fileupload.servlet.ServletFileUpload;
import org.springframework.web.multipart.MultipartFile;

public class UploadServlet {
    private static final long MAX_TOTAL = 50L * 1024 * 1024;

    public List<FileItem> parse(HttpServletRequest request) throws Exception {
        ServletFileUpload upload = new ServletFileUpload(new DiskFileItemFactory());
        upload.setSizeMax(10L * 1024 * 1024);
        upload.setFileSizeMax(5L * 1024 * 1024);
        return upload.parseRequest(request);
    }

    public void unpack(MultipartFile file, Path dir) throws IOException {
        long total = 0;
        byte[] buf = new byte[8192];
        try (ZipInputStream zis = new ZipInputStream(file.getInputStream())) {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                try (OutputStream out = Files.newOutputStream(dir.resolve(entry.getName()))) {
                    int n;
                    while ((n = zis.read(buf)) > 0) {
                        total += n;
                        if (total > MAX_TOTAL) throw new IOException("archive too large");
                        out.write(buf, 0, n);
                    }
                }
            }
        }
    }
}
