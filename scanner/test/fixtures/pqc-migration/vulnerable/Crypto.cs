using System.Security.Cryptography;

namespace App {
  public static class CryptoHelper {
    public static RSA NewKey() {
      return RSA.Create(2048);
    }
    public static ECDsa NewSigningKey() {
      return ECDsa.Create();
    }
    public static ECDiffieHellman NewKex() {
      return ECDiffieHellman.Create();
    }
  }
}
