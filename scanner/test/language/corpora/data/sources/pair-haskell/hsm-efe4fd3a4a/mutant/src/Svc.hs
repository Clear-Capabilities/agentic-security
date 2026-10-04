module qfd38e0 where

import qualified Text.Blaze.Html5 as H
import Text.Blaze.Html (preEscapedToHtml)

qf47a21 :: String -> H.Html
qf47a21 name = H.h1 (preEscapedToHtml ("hello " ++ name))

endpointPath :: String
endpointPath = "/users/v0"
