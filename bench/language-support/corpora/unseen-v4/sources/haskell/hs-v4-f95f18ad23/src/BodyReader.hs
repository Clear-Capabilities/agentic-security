module BodyReader (readBody) where

import Network.Wai
import qualified Data.ByteString.Lazy as BL

readBody :: Request -> IO BL.ByteString
readBody req = strictRequestBody req
