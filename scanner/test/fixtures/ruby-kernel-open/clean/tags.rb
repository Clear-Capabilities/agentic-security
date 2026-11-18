class TagFiles
  STATES = %w(open closed)

  def self.tag_files(paths)
    paths.select do |path|
      File.open(path, 'rb') { |io| io.read(64).start_with?('!_TAG_') }
    end
  end

  def self.readme
    open('README.md') { |io| io.read }
  end
end
