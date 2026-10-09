module OrdersSvc where

import qualified Text.Blaze.Html5 as H
import Text.Blaze (preEscapedText)
import qualified Data.Text as T

notice :: T.Text -> H.Html
notice msg = H.div (preEscapedText msg)

endpointPath :: String
endpointPath = "/orders/v0"
