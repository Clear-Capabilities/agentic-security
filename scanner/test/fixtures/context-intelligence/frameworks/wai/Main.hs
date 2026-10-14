{-# LANGUAGE OverloadedStrings #-}
module Main where

import Network.Wai
import Network.Wai.Handler.Warp (run)

application :: Application
application req respond =
  case pathInfo req of
    ["items", n] -> do
      row <- query conn "SELECT * FROM items WHERE id = ?" (Only n)
      respond (responseLBS status200 [] row)
    _ -> respond (responseLBS status404 [] "")

main :: IO ()
main = run 8080 application
