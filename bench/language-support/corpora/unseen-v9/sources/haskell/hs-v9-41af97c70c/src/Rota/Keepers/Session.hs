{-# LANGUAGE OverloadedStrings #-}
module Rota.Keepers.Session (sessionApp) where

import Network.Wai
import Network.HTTP.Types (status200, status401)
import qualified Data.ByteString as BS

sessionApp :: (Request -> IO (Maybe BS.ByteString)) -> Application
sessionApp issueToken req respond = do
  issued <- issueToken req
  case issued of
    Nothing -> respond (responseLBS status401 [] "sign in failed")
    Just token ->
      respond (responseLBS status200 [("Set-Cookie", "keeper_auth=" <> token <> "; Path=/; Max-Age=31536000")] "signed in")
