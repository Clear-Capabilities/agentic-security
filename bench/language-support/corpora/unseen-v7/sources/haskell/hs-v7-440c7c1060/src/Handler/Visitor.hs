{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE QuasiQuotes #-}
module Handler.Visitor (getVisitorR) where

import Data.Maybe (fromMaybe)
import qualified Data.Text as T
import Yesod.Core

import Foundation

getVisitorR :: Handler Html
getVisitorR = do
  name <- fromMaybe "guest" <$> lookupGetParam "name"
  company <- fromMaybe "" <$> lookupGetParam "company"
  defaultLayout $ do
    setTitle "Visitor badge"
    [whamlet|
      <div .badge>
        <h1>Welcome, #{name}
        $if not (T.null company)
          <p .company>#{company}
        <p .note>Please wear this badge at all times.
    |]
