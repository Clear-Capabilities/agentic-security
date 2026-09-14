fn make_client() -> reqwest::Client {
    reqwest::Client::builder()
        .build()
        .unwrap()
}
