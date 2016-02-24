module Certificate
  def cert_path(file_name)
    File.expand_path(file_name, File.dirname(__FILE__))
  end
end
