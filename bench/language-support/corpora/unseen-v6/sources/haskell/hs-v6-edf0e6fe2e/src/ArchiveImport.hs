{-# LANGUAGE DataKinds, OverloadedStrings, TypeOperators #-}
module ArchiveImport (app) where

import Codec.Compression.GZip (decompress)
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Servant
import qualified Catalog

type API = "archives" :> "import" :> Header "X-Archive-Name" Text :> ReqBody '[OctetStream] BL.ByteString :> Post '[JSON] Int

inflate :: BL.ByteString -> BL.ByteString
inflate = decompress

importHandler :: Maybe Text -> BL.ByteString -> Handler Int
importHandler name body = do
  let label = fromMaybe "unnamed" name
      contents = inflate body
  liftIO (Catalog.loadEntries label contents)

app :: Application
app = serve (Proxy :: Proxy API) importHandler
