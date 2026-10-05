module UsersSvc where

import qualified Lucid as L

badge :: String -> L.Html ()
badge name = L.p_ (L.toHtmlRaw ("hello " ++ name))

endpointPath :: String
endpointPath = "/users/u0"
