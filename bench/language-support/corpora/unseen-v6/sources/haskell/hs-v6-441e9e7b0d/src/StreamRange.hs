{-# LANGUAGE DataKinds, OverloadedStrings, TypeOperators #-}
module StreamRange (app) where

import Control.Monad.IO.Class (liftIO)
import Data.Attoparsec.Text (Parser, char, decimal, endOfInput, parseOnly, string)
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Lazy.Char8 as BLC
import Data.Text (Text)
import Servant
import qualified Media

type API = "stream" :> Capture "asset" Text :> Header "Range" Text :> Get '[OctetStream] BL.ByteString

rangeParser :: Parser (Int, Int)
rangeParser = do
  _ <- string "bytes="
  lo <- decimal
  _ <- char '-'
  hi <- decimal
  endOfInput
  pure (lo, hi)

parseRange :: Text -> Either String (Int, Int)
parseRange = parseOnly rangeParser

streamHandler :: Text -> Maybe Text -> Handler BL.ByteString
streamHandler asset Nothing = liftIO (Media.whole asset)
streamHandler asset (Just header) = case parseRange header of
  Left reason -> throwError err416 { errBody = BLC.pack ("range not understood: " ++ reason) }
  Right (lo, hi) -> liftIO (Media.slice asset lo hi)

app :: Application
app = serve (Proxy :: Proxy API) streamHandler
