{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module OrderHistory (HistoryApi, historyServer) where

import Control.Monad.IO.Class (liftIO)
import Data.Text (Text)
import qualified Data.Vector as V
import qualified Hasql.Connection as Conn
import qualified Hasql.Decoders as D
import qualified Hasql.Encoders as E
import qualified Hasql.Session as Session
import Hasql.Statement (Statement (..))
import Servant

type HistoryApi = "orders" :> "history" :> QueryParam' '[Required] "ref" Text :> Get '[JSON] [Text]

historyServer :: Conn.Connection -> Server HistoryApi
historyServer conn ref = do
  result <- liftIO (Session.run (Session.statement ref linesByReference) conn)
  either (const (throwError err500)) (pure . V.toList) result

linesByReference :: Statement Text (V.Vector Text)
linesByReference = Statement sql encoder decoder True
  where
    sql     = "SELECT sku FROM order_lines WHERE reference = $1 ORDER BY id"
    encoder = E.param (E.nonNullable E.text)
    decoder = D.rowVector (D.column (D.nonNullable D.text))
