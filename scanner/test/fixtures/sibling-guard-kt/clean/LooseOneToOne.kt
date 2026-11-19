// Synthetic fixture: one guarded against one unguarded, but the match is NOT
// tight: the guard takes more than the value and is not named for it. One
// sibling is not a convention unless the pairing is unambiguous.
package example.feeds

class MirrorService(private val http: HttpClient) {

    fun mirror(feedUrl: String, opts: Options): Feed {
        checkInput(feedUrl, opts)
        return http.get(feedUrl).parse()
    }

    fun preview(feedUrl: String): Feed {
        return http.get(feedUrl).parse()
    }
}
