{-# LANGUAGE OverloadedStrings #-}
module Orchard.Drones.Upload (uploadApp) where

import Network.Wai
import Network.HTTP.Types (status201, status405)
import qualified Data.ByteString.Lazy as BL

uploadApp :: (BL.ByteString -> IO ()) -> Application
uploadApp storeFrame req respond
  | requestMethod req /= "PUT" = respond (responseLBS status405 [] "frames are uploaded with PUT")
  | otherwise = do
      frame <- strictRequestBody req
      storeFrame frame
      respond (responseLBS status201 [] "frame stored")
