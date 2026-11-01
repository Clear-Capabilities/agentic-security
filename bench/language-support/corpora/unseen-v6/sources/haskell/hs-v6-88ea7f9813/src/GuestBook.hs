{-# LANGUAGE OverloadedStrings #-}
module GuestBook (main) where

import Control.Monad.IO.Class (liftIO)
import Data.IORef
import qualified Data.Text.Lazy as TL
import Web.Scotty

main :: IO ()
main = do
  entries <- newIORef ([] :: [TL.Text])
  scotty 8080 $ do
    get "/guestbook" $ do
      count <- liftIO (length <$> readIORef entries)
      html ("<html><body><h1>Guest book</h1><p>" <> TL.pack (show count) <> " entries so far</p>" <> form <> "</body></html>")
    post "/guestbook" $ do
      message <- param "message"
      liftIO (modifyIORef entries (message :))
      html ("<html><body><p>Your entry: " <> message <> "</p><a href=/guestbook>back</a></body></html>")

form :: TL.Text
form = "<form method=post action=/guestbook><textarea name=message></textarea><button>Sign</button></form>"
