{-# LANGUAGE OverloadedStrings #-}
module Lab.SampleStatus (sampleStatusApp) where

import qualified Data.ByteString.Lazy as BL
import Data.Int (Int64)
import Data.Text (Text)
import qualified Data.Text.Encoding as TE
import qualified Hasql.Connection as Connection
import qualified Hasql.Decoders as D
import qualified Hasql.Encoders as E
import qualified Hasql.Session as Session
import Hasql.Statement (Statement (..))
import Network.HTTP.Types (status200, status400, status404)
import Network.Wai

statusByBarcode :: Statement Text (Maybe (Int64, Text))
statusByBarcode = Statement sql encoder decoder True
  where
    sql = "select id, status from samples where barcode = $1"
    encoder = E.param (E.nonNullable E.text)
    decoder = D.rowMaybe ((,) <$> D.column (D.nonNullable D.int8) <*> D.column (D.nonNullable D.text))

sampleStatusApp :: Connection.Connection -> Application
sampleStatusApp conn req respond =
  case pathInfo req of
    ["samples", barcode, "status"] -> do
      result <- Session.run (Session.statement barcode statusByBarcode) conn
      case result of
        Right (Just (_, st)) -> respond (responseLBS status200 [] (BL.fromStrict (TE.encodeUtf8 st)))
        Right Nothing -> respond (responseLBS status404 [] "no such sample")
        Left _ -> respond (responseLBS status400 [] "lookup failed")
    _ -> respond (responseLBS status404 [] "not found")
