{-# LANGUAGE OverloadedStrings, QuasiQuotes, TemplateHaskell, TypeFamilies #-}
module BoxOffice.Reviews.Preview where

import Yesod
import Text.Blaze (toMarkup)

data Reviews = Reviews

mkYesod "Reviews" [parseRoutes|
/reviews/preview PreviewR POST
|]

instance Yesod Reviews

instance RenderMessage Reviews FormMessage where
  renderMessage _ _ = defaultFormMessage

postPreviewR :: Handler Html
postPreviewR = do
  body <- runInputPost (ireq textField "body")
  let rendered = toMarkup body :: Html
  defaultLayout [whamlet|
    <h2>Preview of your review
    <blockquote .review>#{rendered}
  |]
