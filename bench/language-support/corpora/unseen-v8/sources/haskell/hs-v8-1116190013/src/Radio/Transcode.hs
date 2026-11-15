{-# LANGUAGE OverloadedStrings #-}
module Radio.Transcode (transcodeRoutes) where

import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Lazy as BL
import qualified Data.Text.Lazy as TL
import Data.Time.Clock.POSIX (getPOSIXTime)
import Network.HTTP.Types.Status (status400)
import Network.Wai.Parse (FileInfo (..))
import System.Process (callCommand)
import Web.Scotty

-- Accepts a programme segment upload and produces the broadcast mp3.
transcodeRoutes :: ScottyM ()
transcodeRoutes =
  post "/segments" $ do
    title <- param "title"
    uploads <- files
    case uploads of
      [(_, FileInfo _ _ content)] -> do
        stamp <- liftIO (round <$> getPOSIXTime) :: ActionM Integer
        let original = "incoming/segment-" ++ show stamp ++ ".wav"
            target = "ready/segment-" ++ show stamp ++ ".mp3"
        liftIO (BL.writeFile original content)
        liftIO (callCommand ("ffmpeg -loglevel error -i " ++ original ++ " -metadata title=\"" ++ TL.unpack title ++ "\" " ++ target))
        text (TL.pack ("queued " ++ target))
      _ -> status status400 >> text "exactly one segment expected"
