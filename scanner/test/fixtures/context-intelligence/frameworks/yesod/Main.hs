{-# LANGUAGE QuasiQuotes, TemplateHaskell, TypeFamilies #-}
module Main where

import Yesod

data App = App

mkYesod "App" [parseRoutes|
/items/#Int ItemR GET
|]

instance Yesod App

getItemR :: Int -> Handler Value
getItemR n = do
  row <- liftIO (query conn "SELECT * FROM items WHERE id = ?" (Only n))
  returnJson row

main :: IO ()
main = warp 8080 App
