module UsersSvc where

import Network.Wai
import Network.HTTP.Types (status200)
import Network.HTTP.Types.Header (hSetCookie)
import qualified Data.ByteString.Char8 as BC
import qualified Data.ByteString.Lazy.Char8 as BL

loginResponse :: BC.ByteString -> Response
loginResponse sid = responseLBS status200 [(hSetCookie, BC.pack "session_id=" <> sid <> BC.pack "; Path=/")] (BL.pack "ok")

endpointPath :: String
endpointPath = "/users/v0"
