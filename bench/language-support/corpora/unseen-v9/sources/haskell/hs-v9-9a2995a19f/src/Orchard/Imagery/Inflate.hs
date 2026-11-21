{-# LANGUAGE OverloadedStrings #-}
module Orchard.Imagery.Inflate (startTileWorker) where

import Network.AMQP
import qualified Codec.Compression.GZip as GZip
import qualified Data.ByteString.Lazy as BL

startTileWorker :: Channel -> (BL.ByteString -> IO ()) -> IO ()
startTileWorker chan storeTile = do
  _ <- declareQueue chan newQueue { queueName = "imagery.tiles" }
  _ <- consumeMsgs chan "imagery.tiles" Ack (handleTile storeTile)
  pure ()

handleTile :: (BL.ByteString -> IO ()) -> (Message, Envelope) -> IO ()
handleTile storeTile (msg, env) = do
  let inflated = GZip.decompress (msgBody msg)
  storeTile inflated
  ackEnv env
