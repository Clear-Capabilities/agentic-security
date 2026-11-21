{-# LANGUAGE OverloadedStrings #-}
module Planetarium.Dome.Hatch (domeRoutes, Dome(..)) where

import Happstack.Server
import Control.Monad (msum, unless)
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Char8 as BC

data Dome = Dome
  { openHatch :: IO ()
  , closeHatch :: IO ()
  , hatchState :: IO String
  }

requireOperator :: (BC.ByteString -> IO Bool) -> ServerPart ()
requireOperator isOperator = do
  req <- askRq
  allowed <- maybe (pure False) (liftIO . isOperator) (getHeader "X-Operator-Token" req)
  unless allowed $ do
    refusal <- unauthorized (toResponse ("operator token required" :: String))
    finishWith refusal

domeRoutes :: (BC.ByteString -> IO Bool) -> Dome -> ServerPart Response
domeRoutes isOperator dome = msum
  [ dir "dome" $ dir "state" $ method GET >> (liftIO (hatchState dome) >>= ok . toResponse)
  , dir "dome" $ dir "close" $ method POST >> requireOperator isOperator >> liftIO (closeHatch dome) >> ok (toResponse ("closing" :: String))
  , dir "dome" $ dir "open" $ method POST >> liftIO (openHatch dome) >> ok (toResponse ("opening" :: String))
  ]
