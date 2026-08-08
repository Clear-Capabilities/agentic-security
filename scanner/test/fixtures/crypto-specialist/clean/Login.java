import java.util.Arrays;

public class Login {
    public boolean check(char[] candidate) {
        char[] password = loadPassword();
        try {
            return java.security.MessageDigest.isEqual(toBytes(password), toBytes(candidate));
        } finally {
            Arrays.fill(password, (char) 0);
        }
    }
}
