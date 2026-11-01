{-# LANGUAGE DataKinds, DeriveGeneric, OverloadedStrings, TypeOperators #-}
module TicketSearch (app) where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (FromJSON, ToJSON)
import Data.Text (Text)
import Database.SQLite.Simple
import GHC.Generics (Generic)
import Servant

data SearchRequest = SearchRequest { searchTerm :: Text, includeClosed :: Bool }
  deriving (Show, Generic)
instance FromJSON SearchRequest

data Ticket = Ticket { ticketId :: Int, title :: Text } deriving (Show, Generic)
instance ToJSON Ticket
instance FromRow Ticket where
  fromRow = Ticket <$> field <*> field

type API = "tickets" :> "search" :> ReqBody '[JSON] SearchRequest :> Post '[JSON] [Ticket]

findTickets :: Connection -> SearchRequest -> IO [Ticket]
findTickets conn req = query_ conn (Query ("SELECT id, title FROM tickets WHERE title LIKE '%" <> searchTerm req <> "%'" <> closedClause))
  where
    closedClause = if includeClosed req then "" else " AND status <> 'closed'"

server :: Connection -> Server API
server conn req = liftIO (findTickets conn req)

app :: Connection -> Application
app conn = serve (Proxy :: Proxy API) (server conn)
