import javax.ws.rs.*;

@Path("/ping")
public class JaxrsPing {
  @GET
  public String ping(@QueryParam("host") String host) throws Exception {
    new ProcessBuilder("sh", "-c", "ping -c 1 " + host).start();
    return "ok";
  }
}