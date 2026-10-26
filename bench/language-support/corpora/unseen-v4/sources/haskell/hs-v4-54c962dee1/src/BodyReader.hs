module BodyReader (readBody) where

import Network.Wai
import Network.Wai.Request (requestSizeCheck)
import qualified Data.ByteString.Lazy as BL

readBody :: Request -> IO BL.ByteString
readBody req = do
  checked <- requestSizeCheck (Just 65536) req
  strictRequestBody checked
