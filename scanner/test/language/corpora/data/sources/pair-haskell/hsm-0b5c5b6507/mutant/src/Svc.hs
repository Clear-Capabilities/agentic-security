module qfd38e0 where

import Web.Scotty
import Control.Monad.IO.Class (liftIO)
import Database.SQLite.Simple
import Network.HTTP.Types.Status (status401)

requireUser :: ActionM Int
requireUser = do
  qdfbfc1 <- header "Authorization"
  case qdfbfc1 of
    Nothing -> status status401 >> finish
    Just _ -> pure 1

main :: IO ()
main = scotty 3000 $ do
  get "/users/:id" $ do
    q2700b2 <- requireUser
    qb19983 <- param "id"
    qc6abe4 <- liftIO (open "users.db")
    qdc8575 <- liftIO (query qc6abe4 "SELECT email FROM users WHERE id = ? AND owner = ?" (qb19983 :: Int, q2700b2))
    json (qdc8575 :: [Only String])

endpointPath :: String
endpointPath = "/users/v0"
