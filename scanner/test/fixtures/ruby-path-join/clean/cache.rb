module Server
  class StaticCache
    def check_static_cache(request)
      return nil unless document_root
      return nil if request.path.split("/").intersect?(%w[. ..])
      cache_path = File.join(document_root, request.path)
      return nil unless File.file?(cache_path)
      File.read(cache_path)
    end
  end
end
