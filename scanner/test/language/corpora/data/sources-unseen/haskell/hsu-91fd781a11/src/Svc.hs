module UsersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401, status403)

main :: IO ()
main = scotty 3000 $ do
  post "/users/note" $ do
    body <- param "body"
    liftIO (appendFile "users.log" (body :: String))
    text "ok"

endpointPath :: String
endpointPath = "/users/u0"
