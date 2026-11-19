# Synthetic fixture: nobody in this file guards the target, so there is no
# convention for any method to deviate from.
class Runner
  def initialize(root)
    @root = root
  end

  def run(target)
    system("make", "-C", @root, target)
  end

  def run_twice(target)
    system("make", "-C", @root, target)
    system("make", "-C", @root, target)
  end

  def check_root
    File.directory?(@root)
  end
end
