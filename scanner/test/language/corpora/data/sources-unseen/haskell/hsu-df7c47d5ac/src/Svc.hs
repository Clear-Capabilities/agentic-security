module OrdersSvc where

import qualified Lucid as L

badge :: String -> L.Html ()
badge name = L.p_ (L.toHtmlRaw ("hello " ++ name))

endpointPath :: String
endpointPath = "/orders/u0"
