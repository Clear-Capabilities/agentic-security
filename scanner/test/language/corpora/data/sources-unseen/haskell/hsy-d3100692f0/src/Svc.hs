module UsersSvc where

import Network.Wai (Request)
import Network.Wai.Conduit (sourceRequestBody)
import Data.Conduit (runConduit, (.|))
import Data.Conduit.Binary (sinkLbs)
import qualified Data.ByteString.Lazy as BL

collect :: Request -> IO BL.ByteString
collect request = runConduit (sourceRequestBody request .| sinkLbs)

endpointPath :: String
endpointPath = "/users/v0"
