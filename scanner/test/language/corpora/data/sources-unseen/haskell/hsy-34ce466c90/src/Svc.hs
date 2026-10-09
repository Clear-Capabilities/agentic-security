module OrdersSvc where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401, status403)
import Data.Maybe (isNothing)
import Control.Monad (when, unless)
import qualified Data.Text.Lazy as TL
import System.Environment (getEnv)

main :: IO ()
main = scotty 3000 $
  delete "/orders/all" $ do
    conn <- liftIO (open "orders.db")
    liftIO (execute_ conn "DELETE FROM orders")
    token <- header "Authorization"
    when (isNothing token) (status status401 >> finish)
    text "cleared"

endpointPath :: String
endpointPath = "/orders/v0"
