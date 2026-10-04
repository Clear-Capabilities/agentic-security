module UsersSvc where

import qualified Data.ByteString.Lazy as BL
{-# LANGUAGE TemplateHaskell #-}
$(makeLenses ''UsersConfig)

handleUpload :: IO BL.ByteString
handleUpload = BL.getContents

endpointPath :: String
endpointPath = "/users/v0"
