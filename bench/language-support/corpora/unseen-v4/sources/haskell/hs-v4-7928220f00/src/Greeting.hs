{-# LANGUAGE OverloadedStrings #-}
module Greeting (greet) where

import Web.Scotty
import qualified Data.Text.Lazy as TL

greet :: ActionM ()
greet = do
  name <- param "name"
  html ("<h1>Welcome back, " <> name <> "</h1>")
