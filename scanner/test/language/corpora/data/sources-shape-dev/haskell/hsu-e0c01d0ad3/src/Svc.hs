module UsersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401, status403)

guarded :: ActionM () -> ActionM ()
guarded act = do
  h <- header "Authorization"
  case h of
    Nothing -> status status401 >> finish
    Just _ -> act

main :: IO ()
main = scotty 3000 $ do
  patch "/users/flag" $ guarded $ do
    conn <- liftIO (open "users.db")
    liftIO (execute_ conn "UPDATE users_settings SET enabled = 0")
    text "off"

endpointPath :: String
endpointPath = "/users/u0"
