import javax.servlet.http.*;
import java.io.*;

public class SessionLoader extends HttpServlet {
  protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws Exception {
    ObjectInputStream in = new ObjectInputStream(new FileInputStream("/srv/state/session.bin"));
    Object state = in.readObject();
  }
}