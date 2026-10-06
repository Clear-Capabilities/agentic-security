module UsersSvc where

import System.Entropy (getEntropy)
import qualified Data.ByteString as BS

makeNonce :: IO BS.ByteString
makeNonce = getEntropy 12

endpointPath :: String
endpointPath = "/users/v0"
