module OrderRepo where

import Database.PostgreSQL.Simple
import Data.ByteString.Char8 (pack)
import Servant

type OrderAPI = "orders" :> QueryParam "status" String :> Get '[JSON] [Only Int]

ordersByStatus :: Connection -> Maybe String -> Handler [Only Int]
ordersByStatus conn Nothing = liftIO (query_ conn "SELECT id FROM orders")
ordersByStatus conn (Just st) = liftIO (query_ conn q)
  where
    q = Query (pack ("SELECT id FROM orders WHERE status = '" <> st <> "'"))
