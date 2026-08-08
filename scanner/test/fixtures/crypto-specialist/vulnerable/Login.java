public class Login {
    public boolean check(String user) {
        String password = System.getenv("PW");
        return password.equals(user);
    }
}
