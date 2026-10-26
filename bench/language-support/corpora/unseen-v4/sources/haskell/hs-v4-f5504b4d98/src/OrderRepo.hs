module OrderRepo where

import Database.PostgreSQL.Simple
import Servant

type OrderAPI = "orders" :> QueryParam "status" String :> Get '[JSON] [Only Int]

ordersByStatus :: Connection -> Maybe String -> Handler [Only Int]
ordersByStatus conn Nothing = liftIO (query_ conn "SELECT id FROM orders")
ordersByStatus conn (Just st) = liftIO (query conn q (Only st))
  where
    q = "SELECT id FROM orders WHERE status = ?"
