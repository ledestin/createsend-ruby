module Certificate
  def cert_path
    File.expand_path('cacert.pem', File.dirname(__FILE__))
  end
end
