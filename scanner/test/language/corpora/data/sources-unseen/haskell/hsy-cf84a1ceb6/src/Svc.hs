module UsersSvc where

import Yesod
import qualified Data.Text as T

renderComment :: T.Text -> Widget
renderComment comment = toWidget (preEscapedToMarkup comment)

endpointPath :: String
endpointPath = "/users/v0"
