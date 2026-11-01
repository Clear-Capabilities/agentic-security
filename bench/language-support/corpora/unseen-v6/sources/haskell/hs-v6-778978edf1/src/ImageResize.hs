{-# LANGUAGE OverloadedStrings #-}
module ImageResize (main) where

import Control.Monad (msum)
import Control.Monad.IO.Class (liftIO)
import Happstack.Server
import System.Process (callCommand)

main :: IO ()
main = simpleHTTP nullConf { port = 8080 } $ msum
  [ dir "resize" resizeHandler
  , notFound (toResponse ("unknown route" :: String))
  ]

resizeHandler :: ServerPart Response
resizeHandler = do
  method POST
  size <- look "size"
  liftIO (callCommand ("convert uploads/latest.png -resize " ++ size ++ " thumbs/latest.png"))
  ok (toResponse ("resized to " ++ size))
