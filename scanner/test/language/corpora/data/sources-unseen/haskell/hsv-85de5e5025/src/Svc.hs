module UsersSvc where

import qualified Text.Blaze.Html as H
import Text.Blaze.Html5 (toHtml)

banner :: String -> H.Html
banner msg = H.p (toHtml msg)

endpointPath :: String
endpointPath = "/users/v0"
