module BadgeHelper
  def badge(label, kind = 'info')
    "<span class=\"badge badge-#{ERB::Util.html_escape(kind)}\">#{ERB::Util.html_escape(label)}</span>".html_safe
  end

  def missing_icon(name)
    message = "icon '#{ERB::Util.html_escape(name)}' not found"
    "<i class=\"missing\"><!-- #{message} --></i>".html_safe
  end

  def count_badge(items)
    "<span class=\"count\">#{items.size}</span>".html_safe
  end

  def plain(label)
    "<span>#{label}</span>"
  end
end
