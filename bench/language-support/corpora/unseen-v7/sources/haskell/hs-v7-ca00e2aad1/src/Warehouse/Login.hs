{-# LANGUAGE OverloadedStrings #-}
module Warehouse.Login (loginPart) where

import Control.Monad.IO.Class (liftIO)
import Crypto.BCrypt (validatePassword)
import qualified Data.ByteString.Base16 as B16
import qualified Data.ByteString.Char8 as BC
import Happstack.Server
import System.Entropy (getEntropy)

import Warehouse.Staff (Picker(..), lookupPicker, storeSession)

loginPart :: ServerPart Response
loginPart = dir "login" $ do
  method POST
  badge <- look "badge"
  pin <- look "pin"
  found <- liftIO (lookupPicker badge)
  case found of
    Just picker | validatePassword (pickerPinHash picker) (BC.pack pin) -> do
      token <- liftIO (BC.unpack . B16.encode <$> getEntropy 32)
      liftIO (storeSession (pickerId picker) token)
      addCookie Session ((mkCookie "sid" token) { secure = True, httpOnly = True })
      ok (toResponse ("signed in" :: String))
    _ -> unauthorized (toResponse ("pin not accepted" :: String))
