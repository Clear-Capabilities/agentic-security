module UsersSvc where

import Network.Wai (Request, strictRequestBody)
import qualified Data.ByteString.Lazy as BL

receive :: Request -> IO BL.ByteString
receive req = strictRequestBody req

endpointPath :: String
endpointPath = "/users/v0"
