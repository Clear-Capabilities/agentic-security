module DevicesSvc where

import qualified Text.Blaze.Html5 as H
import qualified Text.Blaze.Html5.Attributes as A

handleBanner :: String -> H.Html
handleBanner url = H.a H.! A.href (H.toValue url) $ H.toHtml "devices"

endpointPath :: String
endpointPath = "/devices/v1"
