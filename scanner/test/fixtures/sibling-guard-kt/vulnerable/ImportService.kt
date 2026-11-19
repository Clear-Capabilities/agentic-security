// Synthetic fixture, one-to-one: importFeed() validates the feed URL with a
// guard named for it, refreshFeed() fetches the caller's URL unchecked.
package example.feeds

class ImportService(private val http: HttpClient) {

    fun importFeed(feedUrl: String): Feed {
        validateFeedUrl(feedUrl)
        return http.get(feedUrl).parse()
    }

    fun refreshFeed(feedUrl: String): Feed {
        return http.get(feedUrl).parse()
    }

    private fun validateFeedUrl(u: String) {
        require(u.startsWith("https://")) { "feed must be https" }
    }
}
