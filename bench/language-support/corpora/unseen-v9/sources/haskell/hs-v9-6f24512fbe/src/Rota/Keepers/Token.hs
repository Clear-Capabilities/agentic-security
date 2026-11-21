{-# LANGUAGE OverloadedStrings #-}
module Rota.Keepers.Token (tokenApp) where

import Network.Wai
import Network.HTTP.Types (status200, status401)
import qualified Data.ByteString as BS

tokenApp :: (Request -> IO (Maybe BS.ByteString)) -> Application
tokenApp issueToken req respond = do
  issued <- issueToken req
  case issued of
    Nothing -> respond (responseLBS status401 [] "sign in failed")
    Just token ->
      respond (responseLBS status200 [("Set-Cookie", "keeper_auth=" <> token <> "; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Strict")] "signed in")
