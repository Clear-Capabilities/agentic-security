{-# LANGUAGE OverloadedStrings #-}
-- Warp serves this app; Warp is a server, not authorization. The "guard" below is DEFINED but never installed.
module Main where

import Network.Wai
import Network.Wai.Handler.Warp (run)
import Network.HTTP.Types (status200)
import Database.PostgreSQL.Simple
import Auth (authMiddleware, passthroughMiddleware)

router :: Application
router req respond =
  case (requestMethod req, pathInfo req) of
    ("POST", ["transfer"]) -> do
      conn <- connectPostgreSQL "dbname=bank"
      _ <- execute_ conn "UPDATE accounts SET balance = balance - 1"
      respond (responseLBS status200 [] "moved")
    _ -> respond (responseLBS status200 [] "x")

main :: IO ()
main = run 8080 (passthroughMiddleware router)
