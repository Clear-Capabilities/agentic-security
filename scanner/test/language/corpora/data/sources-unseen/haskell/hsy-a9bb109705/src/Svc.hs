module OrdersSvc where

import Network.Wai
import Network.Wai.Handler.Warp (run)
import Network.HTTP.Types (status200, status404)
import Database.SQLite.Simple
import qualified Data.ByteString.Lazy.Char8 as BL
import qualified Data.ByteString.Char8 as BC
import System.Environment (getEnv)

app :: Application
app request respond = case (requestMethod request, pathInfo request) of
  ("POST", ["admin", "reindex"]) -> do
    conn <- open "orders.db"
    execute_ conn "DELETE FROM orders_index"
    respond (responseLBS status200 [] (BL.pack "reindexed"))
  _ -> respond (responseLBS status404 [] BL.empty)

main :: IO ()
main = run 8080 app

endpointPath :: String
endpointPath = "/orders/v0"
