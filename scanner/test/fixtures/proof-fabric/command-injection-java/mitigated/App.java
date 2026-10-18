// Mitigated: an argument vector, no shell, so the input is data and never a command.
public class App {
    public static void main(String[] args) throws Exception {
        String name = args.length > 0 ? args[0] : "";
        new ProcessBuilder("echo", "hello", name).inheritIO().start().waitFor();
    }
}
