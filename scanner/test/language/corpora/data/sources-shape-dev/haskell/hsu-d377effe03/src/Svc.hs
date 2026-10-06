module UsersSvc where

import System.Entropy (getEntropy)
import qualified Data.ByteString as BS

pin :: IO BS.ByteString
pin = getEntropy 8

endpointPath :: String
endpointPath = "/users/u0"
