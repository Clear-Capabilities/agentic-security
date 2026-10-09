module OrdersSvc where

import qualified Lucid as L
import qualified Data.Text as T

note :: T.Text -> L.Html ()
note body = L.div_ [] (L.toHtmlRaw body)

endpointPath :: String
endpointPath = "/orders/v0"
