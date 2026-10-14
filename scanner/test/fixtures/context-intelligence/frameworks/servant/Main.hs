{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
module Main where

import Servant

type API = "items" :> Capture "id" Int :> Get '[JSON] Item

getItem :: Int -> Handler Item
getItem n = do
  row <- liftIO (query conn "SELECT * FROM items WHERE id = ?" (Only n))
  return row

server :: Server API
server = getItem

main :: IO ()
main = run 8080 (serve (Proxy :: Proxy API) server)
