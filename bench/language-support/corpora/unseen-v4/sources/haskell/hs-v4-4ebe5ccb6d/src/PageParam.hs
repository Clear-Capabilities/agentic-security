{-# LANGUAGE OverloadedStrings #-}
module PageParam (listPage) where

import Web.Scotty
import Text.Read (readMaybe)
import qualified Data.Text.Lazy as TL

listPage :: ActionM ()
listPage = do
  raw <- param "page"
  case readMaybe (TL.unpack raw) :: Maybe Int of
    Just page -> json [page * 20 .. page * 20 + 19]
    Nothing   -> text "bad page"
