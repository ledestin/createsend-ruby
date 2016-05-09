module CreateSend
  module Transactional
    class SmartEmail < Base
      attr_reader :smart_email_id

      def self.list(auth, options = nil)
        cs = Base.new auth
        response = cs.get "/transactional/smartemail", :query => options
        response.map{|item| Hashie::Mash.new(item)}
      end

      def initialize(auth, smart_email_id)
        @auth = auth
        @smart_email_id = smart_email_id
        super auth
      end

      def details
        response = get "/transactional/smartemail/#{@smart_email_id}"
        Hashie::Mash.new(response)
      end

      def send(options)
        response = post "/transactional/smartemail/#{@smart_email_id}/send", { :body => options.to_json }
        response.map{|item| Hashie::Mash.new(item)}
      end

    end
  end
end

