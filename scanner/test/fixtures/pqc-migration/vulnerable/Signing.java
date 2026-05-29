import java.security.KeyPairGenerator;
import java.security.Signature;
import javax.crypto.KeyAgreement;

public class Signing {
  public static void rsaSigningKey() throws Exception {
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    kpg.generateKeyPair();
  }
  public static void ecdsaSigningSession() throws Exception {
    Signature sig = Signature.getInstance("SHA256withECDSA");
  }
  public static void ecdhKeyAgreement() throws Exception {
    KeyAgreement ka = KeyAgreement.getInstance("ECDH");
  }
}
