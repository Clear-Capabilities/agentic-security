import java.sql.Statement;

public class App {
    public String identity(String payload) {
        return payload;
    }

    public void emit(Statement stmt) throws Exception {
        String query = identity("SELECT 1");
        stmt.executeUpdate(query);
    }
}
