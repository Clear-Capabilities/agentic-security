{-# LANGUAGE DataKinds, TypeOperators, OverloadedStrings #-}
module OrderLookup (OrderApi, orderServer) where

import Control.Monad.IO.Class (liftIO)
import Data.String (fromString)
import Data.Text (Text)
import qualified Data.Text as T
import Database.SQLite.Simple
import Servant

type OrderApi = "orders" :> QueryParam' '[Required] "ref" Text :> Get '[JSON] [Text]

orderServer :: Connection -> Server OrderApi
orderServer conn ref = liftIO (ordersByReference conn ref)

ordersByReference :: Connection -> Text -> IO [Text]
ordersByReference conn ref = do
  let statement = "SELECT sku FROM order_lines WHERE reference = '" <> T.unpack ref <> "' ORDER BY id"
  rows <- query_ conn (fromString statement) :: IO [Only Text]
  pure (map fromOnly rows)
