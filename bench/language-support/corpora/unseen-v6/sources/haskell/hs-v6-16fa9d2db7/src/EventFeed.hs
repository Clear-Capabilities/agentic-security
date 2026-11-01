{-# LANGUAGE OverloadedStrings #-}
module EventFeed (main) where

import Control.Monad.IO.Class (liftIO)
import Web.Scotty
import qualified Store
import Store (Event)

main :: IO ()
main = scotty 8080 $
  get "/events" $ do
    requested <- param "limit" `rescue` (\_ -> pure 20)
    rows <- liftIO (fetchEvents (clamp requested))
    json rows

clamp :: Int -> Int
clamp n = max 1 (min 100 n)

fetchEvents :: Int -> IO [Event]
fetchEvents n = take n <$> Store.recentEvents
