{-# LANGUAGE OverloadedStrings #-}
module JsonBody (createItem) where

import Data.Aeson
import Network.Wai
import qualified Data.ByteString.Lazy as BL

data Item = Item { name :: String, qty :: Int }

instance FromJSON Item where
  parseJSON = withObject "Item" $ \o -> Item <$> o .: "name" <*> o .: "qty"

createItem :: Request -> IO (Either String Item)
createItem req = do
  body <- strictRequestBody req
  pure (eitherDecode body)
