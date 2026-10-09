module UsersSvc where

import Network.Wai
import Network.Wai.Handler.Warp (run)
import Network.HTTP.Types (status200, status404)
import Database.SQLite.Simple
import qualified Data.ByteString.Lazy.Char8 as BL
import qualified Data.ByteString.Char8 as BC
import System.Environment (getEnv)
import Network.Wai.Middleware.HttpAuth (basicAuth)

app :: Application
app request respond = case (requestMethod request, pathInfo request) of
  ("POST", ["admin", "reindex"]) -> do
    conn <- open "users.db"
    execute_ conn "DELETE FROM users_index"
    respond (responseLBS status200 [] (BL.pack "reindexed"))
  _ -> respond (responseLBS status404 [] BL.empty)

main :: IO ()
main = do
  pass <- getEnv "ADMIN_PASSWORD"
  run 8080 (basicAuth (\u p -> pure (u == BC.pack "admin" && p == BC.pack pass)) "admin area" app)

endpointPath :: String
endpointPath = "/users/v0"
