module OrdersSvc where

import Control.Monad.Logger
import qualified Data.Text as T

onLogin :: T.Text -> T.Text -> LoggingT IO ()
onLogin user _ = logInfoN ("login " <> user)

endpointPath :: String
endpointPath = "/orders/v0"
