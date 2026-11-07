module C605 where
import Crypto.Hash
import qualified Data.ByteString.Char8 as B

digest :: B.ByteString -> Digest SHA256
digest = hash
