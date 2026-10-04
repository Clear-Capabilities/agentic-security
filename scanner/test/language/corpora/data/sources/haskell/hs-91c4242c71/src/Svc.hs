module DevicesSvc where

import qualified Text.Blaze.Html5 as H

handlePage :: String -> H.Html
handlePage name = H.h1 (H.toHtml ("hello " ++ name))

endpointPath :: String
endpointPath = "/devices/v0"
