module OrdersSvc where

import qualified Lucid as L

badge :: String -> L.Html ()
badge name = L.p_ (L.toHtml ("hello " ++ name))

endpointPath :: String
endpointPath = "/orders/u0"
