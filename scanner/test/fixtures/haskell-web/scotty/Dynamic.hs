{-# LANGUAGE OverloadedStrings #-}
-- Routes registered at runtime: the route set cannot be known statically and must be disclosed.
module Main where

import Web.Scotty
import Control.Monad (forM_)
import Data.String (fromString)

names :: [String]
names = ["a", "b", "c"]

main :: IO ()
main = scotty 3000 $ do
  get "/static" $ text "fixed"
  forM_ names $ \n -> get (fromString ("/dyn/" ++ n)) (text "dynamic")
  get (fromString "/also-computed") $ text "computed"
