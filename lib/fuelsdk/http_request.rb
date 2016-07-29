require 'open-uri'
require 'rbconfig'
require 'net/https'
require 'json'

module FuelSDK

  class HTTPResponse < FuelSDK::Response

    def initialize raw, client, request
      super raw, client
      @request = request
    end

    def continue
      rsp = nil
      if more?
       @request['options']['page'] = @results['page'].to_i + 1
       rsp = unpack @client.rest_get(@request['url'], @request['options'])
      else
        puts 'No more data'
      end

      rsp
    end

    def [] key
      @results[key]
    end

    private
      def unpack raw
        @code = raw.code.to_i
        @message = raw.message
        @body = JSON.parse(raw.body) rescue {}
        @results = @body
        @more = ((@results['count'] || @results['totalCount']) > @results['page'] * @results['pageSize']) rescue false
        @success = @message == 'OK'
      end

      # by default try everything against results
      def method_missing method, *args, &block
        @results.send(method, *args, &block)
      end
  end

  module HTTPRequest

    request_methods = ['get', 'post', 'patch', 'delete']
    request_methods.each do |method|
      class_eval <<-EOT, __FILE__, __LINE__ + 1
        def #{method}(url, options={})                                      # def post(url, options)
          request Net::HTTP::#{method.capitalize}, url, options             #   request Net::HTTP::Post, url, options
        end                                                                 # end
      EOT
    end

    private

      def generate_uri(url, params=nil)
        uri = URI.parse(url)
        uri.query = URI.encode_www_form(params) if params
        uri
      end

      def request(method, url, options={})
        puts "http_request; method: #{method.inspect}, url: #{url.inspect}, options: #{options.inspect}"
        uri = generate_uri url, options['params']

        openssl_dir = OpenSSL::X509::DEFAULT_CERT_AREA
        mac_openssl = '/System/Library/OpenSSL' == openssl_dir

        puts "%s: %s" % [OpenSSL::OPENSSL_VERSION, openssl_dir]
        [OpenSSL::X509::DEFAULT_CERT_DIR_ENV, OpenSSL::X509::DEFAULT_CERT_FILE_ENV].each do |key|
          puts "%s=%s" % [key, ENV[key].to_s.inspect]
        end

        ca_file = ENV[OpenSSL::X509::DEFAULT_CERT_FILE_ENV] || OpenSSL::X509::DEFAULT_CERT_FILE
        ca_path = (ENV[OpenSSL::X509::DEFAULT_CERT_DIR_ENV] || OpenSSL::X509::DEFAULT_CERT_DIR).chomp('/')
        puts "#{OpenSSL::X509::DEFAULT_CERT_FILE_ENV.inspect}, #{ENV[OpenSSL::X509::DEFAULT_CERT_FILE_ENV].inspect}, #{OpenSSL::X509::DEFAULT_CERT_FILE.inspect}"
        puts "#{OpenSSL::X509::DEFAULT_CERT_DIR_ENV.inspect}, #{ENV[OpenSSL::X509::DEFAULT_CERT_DIR_ENV].inspect}, #{OpenSSL::X509::DEFAULT_CERT_DIR.inspect}"

        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = true

        http.cert_store = OpenSSL::X509::Store.new
        http.cert_store.set_default_paths

        http.verify_mode = OpenSSL::SSL::VERIFY_PEER

        http.ca_file = ca_file
        http.ca_path = ca_path

        data = options['data']
        _request = method.new uri.request_uri
        _request.body = data.to_json if data
        _request.content_type = options['content_type'] if options['content_type']

        failed_cert = failed_cert_reason = nil

        if mac_openssl
          warn "warning: will not be able show failed certificate info on OS X's OpenSSL"
          # This drives me absolutely nuts. It seems that on Rubies compiled against OS X's
          # system OpenSSL, the mere fact of defining a `verify_callback` makes the
          # cert verification fail for requests that would otherwise be successful.
        else
          http.verify_callback = lambda { |verify_ok, store_context|
            if !verify_ok
              failed_cert = store_context.current_cert
              failed_cert_reason = "%d: %s" % [ store_context.error, store_context.error_string ]
            end
            verify_ok
          }
        end

        begin
          response = http.request(_request)

        rescue Errno::ECONNREFUSED
          puts "Error: connection refused"
          exit 1
        rescue OpenSSL::SSL::SSLError => e
          puts "#{e.class}: #{e.message}"

          if failed_cert
            puts "\nThe server presented a certificate that could not be verified:"
            puts "  subject: #{failed_cert.subject}"
            puts "  issuer: #{failed_cert.issuer}"
            puts "  error code %s" % failed_cert_reason
          end

          ca_file_missing = !File.exist?(ca_file) && !mac_openssl
          ca_path_empty = Dir["#{ca_path}/*"].empty?

          if ca_file_missing || ca_path_empty
            puts "\nPossible causes:"
            puts "  `%s' does not exist" % ca_file if ca_file_missing
            puts "  `%s/' is empty" % ca_path if ca_path_empty
          end

          exit 1
        rescue HTTPI::SSLError => e

          #client.ssl_config.add_trust_ca("/etc/ssl/certs")

          puts 'rescuing the httpi error!'
          puts "#{e.class}: #{e.message}"

          if failed_cert
            puts "\nThe server presented a certificate that could not be verified:"
            puts "  subject: #{failed_cert.subject}"
            puts "  issuer: #{failed_cert.issuer}"
            puts "  error code %s" % failed_cert_reason
          end

          ca_file_missing = !File.exist?(ca_file) && !mac_openssl
          ca_path_empty = Dir["#{ca_path}/*"].empty?

          if ca_file_missing || ca_path_empty
            puts "\nPossible causes:"
            puts "  `%s' does not exist" % ca_file if ca_file_missing
            puts "  `%s/' is empty" % ca_path if ca_path_empty
          end

          exit 1
        end

        puts 'done sending request'
        begin
          puts 'setup response...'
          puts "url: #{url.inspect}"
          puts "options: #{options.inspect}"
          puts "response: #{response.inspect}"
          HTTPResponse.new(response, self, :url => url, :options => options)
        rescue HTTPI::SSLError => e

          #client.ssl_config.add_trust_ca("/etc/ssl/certs")

          puts 'rescuing the httpi error!'
          puts "#{e.class}: #{e.message}"

          if failed_cert
            puts "\nThe server presented a certificate that could not be verified:"
            puts "  subject: #{failed_cert.subject}"
            puts "  issuer: #{failed_cert.issuer}"
            puts "  error code %s" % failed_cert_reason
          end

          ca_file_missing = !File.exist?(ca_file) && !mac_openssl
          ca_path_empty = Dir["#{ca_path}/*"].empty?

          if ca_file_missing || ca_path_empty
            puts "\nPossible causes:"
            puts "  `%s' does not exist" % ca_file if ca_file_missing
            puts "  `%s/' is empty" % ca_path if ca_path_empty
          end

          exit 1
        end
      end
  end
end
