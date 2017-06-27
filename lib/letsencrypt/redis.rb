# frozen_string_literal: true

module LetsEncrypt
  # :nodoc:
  class Redis
    class << self
      def connection
        @connection ||= ::Redis.new(url: LetsEncrypt.config.redis_url)
      end

      # Save certificate into redis.
      def save(cert)
        cert.all_domains.each do |domain|
          LetsEncrypt.logger.info "Save #{domain}'s certificate to redis"
          connection.set "#{domain}.key", cert.key
          connection.set "#{domain}.crt", cert.certificate
        end
      end
    end
  end
end
