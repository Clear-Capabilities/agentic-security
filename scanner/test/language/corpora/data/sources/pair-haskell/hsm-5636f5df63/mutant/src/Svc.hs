module qfd38e0 where

import qualified Data.ByteString.Lazy as BL

q4c2b61 :: IO BL.ByteString
q4c2b61 = fmap (BL.take 65536) BL.getContents

endpointPath :: String
endpointPath = "/users/v0"
