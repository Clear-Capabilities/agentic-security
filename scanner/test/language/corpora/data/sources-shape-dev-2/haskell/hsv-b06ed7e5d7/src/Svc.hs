module OrdersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401, status403)
import Data.Maybe (isNothing)
import Control.Monad (when, unless)

main :: IO ()
main = scotty 3000 $
  delete "/orders/all" $ do
    mk <- header "X-Api-Key"
    case mk of
      Nothing -> status status403 >> finish
      Just _ -> do
        conn <- liftIO (open "orders.db")
        liftIO (execute_ conn "DELETE FROM orders")
        text "cleared"

endpointPath :: String
endpointPath = "/orders/v0"
