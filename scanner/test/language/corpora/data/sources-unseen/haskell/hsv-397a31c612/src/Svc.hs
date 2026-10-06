module UsersSvc where

import qualified Lucid as L
import qualified Data.Text as T

note :: T.Text -> L.Html ()
note body = L.div_ [] (L.toHtml body)

endpointPath :: String
endpointPath = "/users/v0"
