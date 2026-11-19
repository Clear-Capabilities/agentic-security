# Synthetic fixture, fixed twin: every build validates the target first.
class Packager
  def initialize(root)
    @root = root
  end

  def build(target)
    validate_target!(target)
    system("make", "-C", @root, target)
  end

  def package(target, version)
    validate_target! target
    system("make", "-C", @root, target)
    "#{target}-#{version}.tar.gz"
  end

  def rebuild(target)
    validate_target!(target)
    system("make", "-C", @root, "clean")
    system("make", "-C", @root, target)
  end

  private

  def validate_target!(target)
    raise ArgumentError, "bad target" unless target.match?(/\A[a-z][a-z0-9_-]*\z/)
  end
end
