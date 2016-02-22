require 'cgi'
require 'uri'
require 'httparty'
require 'hashie'
require 'json'
require 'active_support/core_ext/object/to_query'

module CreateSend

  USER_AGENT_STRING = "createsend-ruby-#{VERSION}-#{RUBY_VERSION}-p#{RUBY_PATCHLEVEL}-#{RUBY_PLATFORM}"

  # Represents a CreateSend API error. Contains specific data about the error.
  class CreateSendError < StandardError
    attr_reader :data

    def initialize(data)
      @data = data
      super format_data_as_message
    end

    private

    def format_data_as_message
      extra_result_data = "\nExtra result data: #{@data.ResultData}" \
        if @data.ResultData
      "The CreateSend API responded with the following error"\
        " - #{@data.Code}: #{@data.Message}#{extra_result_data}"
    end
  end

  # Raised for HTTP response codes of 400...500
  class ClientError < StandardError; end
  # Raised for HTTP response codes of 500...600
  class ServerError < StandardError; end
  # Raised for HTTP response code of 400
  class BadRequest < CreateSendError; end
  # Raised for HTTP response code of 401
  class Unauthorized < CreateSendError; end
  # Raised for HTTP response code of 404
  class NotFound < ClientError; end

  # Raised for HTTP response code of 401, specifically when an OAuth token
  # in invalid (Code: 120, Message: 'Invalid OAuth Token')
  class InvalidOAuthToken < Unauthorized; end
  # Raised for HTTP response code of 401, specifically when an OAuth token
  # has expired (Code: 121, Message: 'Expired OAuth Token')
  class ExpiredOAuthToken < Unauthorized; end
  # Raised for HTTP response code of 401, specifically when an OAuth token
  # has been revoked (Code: 122, Message: 'Revoked OAuth Token')
  class RevokedOAuthToken < Unauthorized; end

  class TokenResponse
    ATTRS = %w(access_token expires_in refresh_token)

    attr_reader *ATTRS

    def self.from_hash(hash)
      self.new *hash.values_at(*ATTRS)
    end

    def initialize(access_token, expires_in, refresh_token)
      @access_token, @expires_in, @refresh_token =
        access_token, expires_in, refresh_token
    end
  end

  # Provides high level CreateSend functionality/data you'll probably need.
  class CreateSend
    extend Certificate
    include HTTParty

    @@base_uri = "https://api.createsend.com/api/v3.1"
    @@oauth_base_uri = "https://api.createsend.com/oauth"
    @@oauth_token_uri = "#{@@oauth_base_uri}/token"

    # Specify cert authority file for cert validation
    ssl_ca_file cert_path

    headers({
      'User-Agent' => USER_AGENT_STRING,
      'Content-Type' => 'application/json; charset=utf-8',
      'Accept-Encoding' => 'gzip, deflate' })
    base_uri @@base_uri

    # Set a custom user agent string to be used when instances of
    # CreateSend::CreateSend make API calls.
    #
    # user_agent - The user agent string to use in the User-Agent header when
    #              instances of this class make API calls.
    def self.user_agent(user_agent)
      headers({'User-Agent' => user_agent})
    end

    # Set user agent to be CreateSend.
    def self.default_user_agent
      user_agent USER_AGENT_STRING
    end

    # Get the authorization URL for your application, given the application's
    # client_id, redirect_uri, scope, and optional state data.
    def self.authorize_url(client_id, redirect_uri, scope, state=nil)
      params = {
        client_id: client_id, redirect_uri: redirect_uri, scope: scope
      }
      params[:state] = state if state
      "#{@@oauth_base_uri}?#{params.to_query}"
    end

    # Exchange a provided OAuth code for an OAuth access token, 'expires in'
    # value, and refresh token.
    def self.exchange_token(client_id, client_secret, redirect_uri, code)
      response = request_token(client_id, client_secret, redirect_uri, code)
      fail_if_bad_response(response, 'Error exchanging code for access token')
      TokenResponse.from_hash response
    end

    # Refresh an OAuth access token, given an OAuth refresh token.
    # Returns a new access token, 'expires in' value, and refresh token.
    def self.refresh_access_token(refresh_token)
      response = request_access_token(refresh_token)
      fail_if_bad_response(response, 'Error refreshing access token')
      TokenResponse.from_hash response
    end

    class << self
      private

      def cs_method(*names)
        names.each { |name| define_cs_method name }
      end

      def define_cs_method(name)
        define_method(name) do |*args|
          args[1] = add_auth_details_to_options(args[1])
          handle_response CreateSend.send(name, *args)
        end
        alias_method "cs_#{name}", name
      end

      def fail_if_bad_response(response, message)
        raise format_response_error_message(response, message) \
          if erroneous?(response)
      end

      def format_response_error_message(response, message)
        err = "#{message}: "
        err << "#{response['error']} - #{response['error_description']}"
      end

      def erroneous?(response)
        response.has_key? 'error' and response.has_key? 'error_description'
      end

      def request_access_token(refresh_token)
        body = {
          grant_type: 'refresh_token',
          refresh_token: refresh_token
        }.to_query
        HTTParty.post(@@oauth_token_uri, body: body)
      end

      def request_token(client_id, client_secret, redirect_uri, code)
        body = {
          grant_type: 'authorization_code',
          client_id: client_id,
          client_secret: client_secret,
          redirect_uri: redirect_uri,
          code: code
        }.to_query
        HTTParty.post(@@oauth_token_uri, {:body => body})
      end
    end

    attr_reader :auth_details

    def initialize(*args)
      return if args.empty?

      auth args.first # Expect auth details as first argument
    end

    # Authenticate using either OAuth or an API key.
    def auth(auth_details)
      @auth_details = auth_details
    end

    # Refresh the current OAuth token using the current refresh token.
    def refresh_token
      raise '@auth_details[:refresh_token] does not contain a refresh token.' \
        unless @auth_details && refresh_token = @auth_details[:refresh_token]

      response = self.class.refresh_access_token refresh_token
      auth({
        :access_token => response.access_token,
        :refresh_token => response.refresh_token})
      response
    end

    # Gets your clients.
    def clients
      response = get('/clients.json')
      response.map { |item| Hashie::Mash.new(item) }
    end

    # Get your billing details.
    def billing_details
      response = get('/billingdetails.json')
      Hashie::Mash.new(response)
    end

    # Gets valid countries.
    def countries
      response = get('/countries.json')
      response.parsed_response
    end

    # Gets the current date in your account's timezone.
    def systemdate
      response = get('/systemdate.json')
      Hashie::Mash.new(response)
    end

    # Gets valid timezones.
    def timezones
      response = get('/timezones.json')
      response.parsed_response
    end

    # Gets the administrators for the account.
    def administrators
      response = get('/admins.json')
      response.map{|item| Hashie::Mash.new(item)}
    end

    # Gets the primary contact for the account.
    def get_primary_contact
      response = get('/primarycontact.json')
      Hashie::Mash.new(response)
    end

    # Set the primary contect for the account.
    def set_primary_contact(email)
      options = { :query => { :email => email } }
      response = put("/primarycontact.json", options)
      Hashie::Mash.new(response)
    end

    # Get a URL which initiates a new external session for the user with the
    # given email.
    # Full details: http://www.campaignmonitor.com/api/account/#single_sign_on
    #
    # email         - The email address of the Campaign Monitor user for whom
    #                 the login session should be created.
    # chrome        - Which 'chrome' to display - Must be either "all",
    #                 "tabs", or "none".
    # url           - The URL to display once logged in. e.g. "/subscribers/"
    # integrator_id - The integrator ID. You need to contact Campaign Monitor
    #                 support to get an integrator ID.
    # client_id     - The Client ID of the client which should be active once
    #                 logged in to the Campaign Monitor account.
    #
    # Returns An object containing a single field SessionUrl which represents
    # the URL to initiate the external Campaign Monitor session.
    def external_session_url(email, chrome, url, integrator_id, client_id)
      body = {
        :Email => email,
        :Chrome => chrome,
        :Url => url,
        :IntegratorID => integrator_id,
        :ClientID => client_id }.to_json
      response = put("/externalsession.json", body: body)
      Hashie::Mash.new(response)
    end

    cs_method :get, :post, :put, :delete

    def add_auth_details_to_options(options)
      return options unless @auth_details

      options ||= {}
      if @auth_details.has_key? :access_token
        options[:headers] = {
          "Authorization" => "Bearer #{@auth_details[:access_token]}" }
      elsif @auth_details.has_key? :api_key
        unless options.has_key? :basic_auth
          options[:basic_auth] = {
            :username => @auth_details[:api_key], :password => 'x' }
        end
      end
      options
    end

    def handle_response(response) # :nodoc:
      case response.code
      when 400
        raise BadRequest.new(Hashie::Mash.new response)
      when 401
        data = Hashie::Mash.new(response)
        case data.Code
        when 120
          raise InvalidOAuthToken.new data
        when 121
          raise ExpiredOAuthToken.new data
        when 122
          raise RevokedOAuthToken.new data
        else
          raise Unauthorized.new data
        end
      when 404
        raise NotFound.new
      when 400...500
        raise ClientError.new
      when 500...600
        raise ServerError.new
      else
        response
      end
    end
  end
end
