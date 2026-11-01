{-# LANGUAGE OverloadedStrings, QuasiQuotes, TemplateHaskell #-}
module TeamRoster (getRosterR) where

import Data.Text (Text)
import Text.Blaze.Html (Html, toHtml)
import Yesod.Core
import Foundation (Handler)

data Member = Member { memberName :: Text, memberRole :: Text }

getRosterR :: Text -> Handler Html
getRosterR teamName = do
  highlight <- lookupGetParam "highlight"
  let members = [Member "Ada" "lead", Member "Grace" "engineer", Member "Linus" "operator"]
  defaultLayout $ do
    setTitle (toHtml ("Roster for " <> teamName))
    [whamlet|
      <h1>Team #{teamName}
      $maybe h <- highlight
        <p .notice>Highlighting #{h}
      <ul>
        $forall m <- members
          <li>#{memberName m} (#{memberRole m})
    |]
