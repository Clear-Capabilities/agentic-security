{-# LANGUAGE DataKinds, OverloadedStrings, TypeOperators #-}
module MediaRange (app) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import qualified Data.Text as T
import Servant
import qualified Media

type API = "media" :> Capture "asset" Text :> Header "Range" Text :> Get '[OctetStream] BL.ByteString

parseRange :: Text -> (Int, Int)
parseRange header = let [lo, hi] = T.splitOn "-" (T.splitOn "=" header !! 1) in (read (T.unpack lo), read (T.unpack hi))

mediaHandler :: Text -> Maybe Text -> Handler BL.ByteString
mediaHandler asset Nothing = liftIO (Media.whole asset)
mediaHandler asset (Just header) = do
  let (lo, hi) = parseRange header
  liftIO (Media.slice asset lo hi)

app :: Application
app = serve (Proxy :: Proxy API) mediaHandler
