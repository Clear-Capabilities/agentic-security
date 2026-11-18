module BadgeHelper
  def badge(label, kind = 'info')
    "<span class=\"badge badge-#{kind}\">#{label}</span>".html_safe
  end

  def missing_icon(name)
    message = "icon '#{name}' not found"
    "<i class=\"missing\"><!-- #{message} --></i>".html_safe
  end
end
