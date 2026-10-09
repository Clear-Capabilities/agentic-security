module UsersSvc where

import Network.Wai (Request, RequestBodyLength (..), requestBodyLength, strictRequestBody)
import qualified Data.ByteString.Lazy as BL

collect :: Request -> IO BL.ByteString
collect request = case requestBodyLength request of
  KnownLength size | size <= 65536 -> strictRequestBody request
  _ -> pure BL.empty

endpointPath :: String
endpointPath = "/users/v0"
