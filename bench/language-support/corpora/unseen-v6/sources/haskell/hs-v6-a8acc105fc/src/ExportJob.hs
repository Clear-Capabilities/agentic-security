{-# LANGUAGE DeriveGeneric, OverloadedStrings, RecordWildCards #-}
module ExportJob (main) where

import Data.Aeson (FromJSON, decode)
import qualified Data.ByteString.Lazy as BL
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import GHC.Generics (Generic)
import Network.AMQP

data ExportRequest = ExportRequest { accountId :: Int, outputName :: Text, format :: Text }
  deriving (Show, Generic)
instance FromJSON ExportRequest

exportRoot :: FilePath
exportRoot = "/var/exports/"

main :: IO ()
main = do
  conn <- openConnection "127.0.0.1" "/" "guest" "guest"
  chan <- openChannel conn
  _ <- declareQueue chan newQueue { queueName = "exports" }
  _ <- consumeMsgs chan "exports" Ack onMessage
  putStrLn "export worker ready"
  where
    onMessage (msg, env) = do
      case decode (msgBody msg) of
        Just req -> runExport req
        Nothing -> putStrLn "discarding malformed export request"
      ackEnv env

runExport :: ExportRequest -> IO ()
runExport ExportRequest{..} = do
  rows <- renderRows accountId format
  BL.writeFile (exportRoot ++ T.unpack outputName) rows

renderRows :: Int -> Text -> IO BL.ByteString
renderRows account fmt = pure (BL.fromStrict (TE.encodeUtf8 (T.pack (show account) <> "," <> fmt)))
