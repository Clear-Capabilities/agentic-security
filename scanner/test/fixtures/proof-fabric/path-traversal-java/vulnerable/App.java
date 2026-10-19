// Deliberately vulnerable: user input is joined onto a base directory with no traversal check (CWE-22).
import java.nio.file.*;

public class App {
    public static void main(String[] args) throws Exception {
        Path base = Paths.get("public");
        Files.createDirectories(base);
        String requested = args.length > 0 ? args[0] : "";
        try { Files.writeString(base.resolve(requested), "written-by-fixture"); } catch (Exception e) { /* ignore */ }
    }
}
