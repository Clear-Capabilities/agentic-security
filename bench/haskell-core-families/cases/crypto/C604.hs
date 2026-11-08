module C604 where
import Crypto.Random
import qualified Data.ByteString as B

newToken :: IO B.ByteString
newToken = getRandomBytes 32
