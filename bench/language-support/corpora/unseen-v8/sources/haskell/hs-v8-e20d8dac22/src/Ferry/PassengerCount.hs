{-# LANGUAGE OverloadedStrings #-}
module Ferry.PassengerCount (fareRoutes) where

import Data.Maybe (fromMaybe)
import qualified Data.Text.Lazy as TL
import Text.Read (readMaybe)
import Web.Scotty

adultFare, childFare :: Int
adultFare = 1850
childFare = 920

quote :: Int -> Int -> Int
quote adults children = adults * adultFare + children * childFare

fareRoutes :: ScottyM ()
fareRoutes =
  get "/fares/quote" $ do
    adultsRaw <- param "adults" :: ActionM TL.Text
    childrenRaw <- param "children" `rescue` (\_ -> pure "0") :: ActionM TL.Text
    let adults = read (TL.unpack adultsRaw) :: Int
        children = fromMaybe 0 (readMaybe (TL.unpack childrenRaw))
    text (TL.pack (show (quote adults children)))
