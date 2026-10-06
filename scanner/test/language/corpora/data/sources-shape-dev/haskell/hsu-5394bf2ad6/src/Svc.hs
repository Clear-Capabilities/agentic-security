module UsersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401, status403)
import Control.Monad (when)

requireToken :: ActionM ()
requireToken = do
  k <- header "Authorization"
  when (k == Nothing) (status status401 >> finish)

main :: IO ()
main = scotty 3000 $ do
  post "/users/note" $ do
    requireToken
    body <- param "body"
    liftIO (appendFile "users.log" (body :: String))
    text "ok"

endpointPath :: String
endpointPath = "/users/u0"
