// Deliberately vulnerable: untrusted input is concatenated into a shell command (CWE-78).
public class App {
    public static void main(String[] args) throws Exception {
        String name = args.length > 0 ? args[0] : "";
        new ProcessBuilder("sh", "-c", "echo hello " + name).inheritIO().start().waitFor();
    }
}
