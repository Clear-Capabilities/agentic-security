module UsersSvc where

import Web.Scotty
import Web.Scotty.Cookie (setSimpleCookie)
import qualified Data.Text as T

login :: T.Text -> ActionM ()
login sid = do
  setSimpleCookie "session_id" sid
  text "welcome"

endpointPath :: String
endpointPath = "/users/v0"
