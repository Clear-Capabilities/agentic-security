// Mitigated: the resolved path is normalized and confined to the base directory before any write.
import java.nio.file.*;

public class App {
    public static void main(String[] args) throws Exception {
        Path base = Paths.get("public").toAbsolutePath().normalize();
        Files.createDirectories(base);
        String requested = args.length > 0 ? args[0] : "";
        Path target = base.resolve(requested).normalize();
        if (target.startsWith(base) && !target.equals(base)) Files.writeString(target, "written-by-fixture");
    }
}
