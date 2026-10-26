{-# LANGUAGE OverloadedStrings #-}
module PageParam (listPage) where

import Web.Scotty
import qualified Data.Text.Lazy as TL

listPage :: ActionM ()
listPage = do
  raw <- param "page"
  let page = read (TL.unpack raw) :: Int
  json [page * 20 .. page * 20 + 19]
