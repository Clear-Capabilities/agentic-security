require 'uri'

module ReturnGuard
  def self.check_redirect(target)
    return if target =~ URI::DEFAULT_PARSER.regexp[:ABS_PATH] && URI(target).host.nil? && !target.start_with?("//")
    raise ArgumentError, "redirect target #{target} is not local"
  end
end
