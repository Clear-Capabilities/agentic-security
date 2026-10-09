module OrdersSvc where

import Control.Monad.Logger
import qualified Data.Text as T

onLogin :: T.Text -> T.Text -> LoggingT IO ()
onLogin user password = logInfoN ("login " <> user <> " password=" <> password)

endpointPath :: String
endpointPath = "/orders/v0"
