// Synthetic fixture, fixed twin: both paths validate the feed URL.
package example.feeds

class ImportService(private val http: HttpClient) {

    fun importFeed(feedUrl: String): Feed {
        validateFeedUrl(feedUrl)
        return http.get(feedUrl).parse()
    }

    fun refreshFeed(feedUrl: String): Feed {
        validateFeedUrl(feedUrl)
        return http.get(feedUrl).parse()
    }

    private fun validateFeedUrl(u: String) {
        require(u.startsWith("https://")) { "feed must be https" }
    }
}
