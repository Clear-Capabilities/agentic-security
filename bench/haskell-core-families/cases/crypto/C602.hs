module C602 where
import Crypto.Hash
import qualified Data.ByteString.Char8 as B

digest :: B.ByteString -> Digest MD5
digest = hash
