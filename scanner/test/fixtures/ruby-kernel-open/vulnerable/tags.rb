class TagFiles
  def self.tag_files(paths)
    paths.select do |path|
      open(path, 'rb') { |io| io.read(64).start_with?('!_TAG_') }
    end
  end
end
