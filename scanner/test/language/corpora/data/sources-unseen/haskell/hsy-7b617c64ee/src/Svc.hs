module OrdersSvc where

import Web.Scotty
import Web.Scotty.Cookie (setSimpleCookie)
import qualified Data.Text as T

rememberLanguage :: T.Text -> ActionM ()
rememberLanguage lang = do
  setSimpleCookie "language" lang
  text "saved"

endpointPath :: String
endpointPath = "/orders/v0"
