module OrdersSvc where

import Yesod
import qualified Data.Text as T

renderComment :: T.Text -> Widget
renderComment comment = toWidget (preEscapedToMarkup comment)

endpointPath :: String
endpointPath = "/orders/v0"
