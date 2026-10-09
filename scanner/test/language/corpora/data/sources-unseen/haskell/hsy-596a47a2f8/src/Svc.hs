module OrdersSvc where

import Network.Wai (Request)
import Network.Wai.Conduit (sourceRequestBody)
import Data.Conduit (runConduit, (.|))
import Data.Conduit.Binary (sinkLbs, isolate)
import qualified Data.ByteString.Lazy as BL

collect :: Request -> IO BL.ByteString
collect request = runConduit (sourceRequestBody request .| isolate 65536 .| sinkLbs)

endpointPath :: String
endpointPath = "/orders/v0"
