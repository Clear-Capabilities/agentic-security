module OrdersSvc where

import qualified Text.Blaze.Html as H
import Text.Blaze.Html5 (preEscapedToHtml)

banner :: String -> H.Html
banner msg = preEscapedToHtml msg

endpointPath :: String
endpointPath = "/orders/v0"
