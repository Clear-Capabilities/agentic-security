module UsersSvc where

import qualified Text.Blaze.Html5 as H

snippet :: String -> H.Html
snippet who = H.div (H.toHtml who)

endpointPath :: String
endpointPath = "/users/u0"
