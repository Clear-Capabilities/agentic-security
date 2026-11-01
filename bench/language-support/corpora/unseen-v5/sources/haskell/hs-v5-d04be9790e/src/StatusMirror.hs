{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings, DeriveGeneric #-}
module StatusMirror (MirrorApi, mirrorServer) where

import Control.Lens ((^.))
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON)
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
import Network.Wreq (get, responseBody)
import Servant

data Upstream = Upstream { upstreamHost :: Text, upstreamLabel :: Text }
  deriving (Generic)

instance FromJSON Upstream

type MirrorApi = "mirror" :> ReqBody '[JSON] Upstream :> Post '[OctetStream] BL.ByteString

mirrorServer :: Server MirrorApi
mirrorServer upstream = liftIO (fetchStatus upstream)

fetchStatus :: Upstream -> IO BL.ByteString
fetchStatus u = do
  r <- get ("https://" <> T.unpack (upstreamHost u) <> "/status.json")
  pure (r ^. responseBody)
