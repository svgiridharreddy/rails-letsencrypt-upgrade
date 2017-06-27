# frozen_string_literal: true

module LetsEncrypt
  # :nodoc:
  module CertificateVerifiable
    extend ActiveSupport::Concern


    def verify
      domains = [domain] + [alternative_names]
      domains.each do |domain|
        if !verify_domain(domain)
          logger.info "Cannot verify domain: #{domain}. Certificate is not verified!"
          self.verified = false
          save!
          return
        end
      end
      # Mark as verified
      self.verified = true
      # Save this certificate
      save!
    end

    # Returns true if verify domain is succeed.
    def verify_domain(domain)
      start_authorize(domain)
      start_challenge(domain)
      wait_verify_status
      check_verify_status
    rescue Acme::Client::Error => e
      retry_on_verify_error(e)
    end

    private

    def start_authorize(domain)
      authorization = LetsEncrypt.client.authorize(domain: domain)
      clear_previous_verification_data
      @challenge = authorization.http01
      connection = LetsEncrypt::Redis.connection
      connection.set("verification_path.#{@challenge.filename}", @challenge.file_content)
    end

    def start_challenge(domain)
      logger.info "Attempting verification of #{domain}"
      @challenge.request_verification
    end

    def wait_verify_status
      checks = 0
      until @challenge.verify_status != 'pending'
        checks += 1
        if checks > 30
          logger.info 'Status remained at pending for 30 checks'
          return false
        end
        sleep 1
      end
    end

    def check_verify_status
      unless @challenge.verify_status == 'valid'
        logger.info "Status was not valid (was: #{@challenge.verify_status})"
        return false
      end
      # Clean verification data
      clear_previous_verification_data
      true
    end

    def clear_previous_verification_data
      return unless @challenge
      connection = LetsEncrypt::Redis.connection
      connection.del("verification_path.#{@challenge.filename}")
    end

    def retry_on_verify_error(e)
      @retries ||= 0
      if e.is_a?(Acme::Client::Error::BadNonce) && @retries < 5
        @retries += 1
        logger.info "Bad nounce encountered. Retrying (#{@retries} of 5 attempts)"
        sleep 1
        verify
      else
        logger.info "Error: #{e.class} (#{e.message})"
        clear_previous_verification_data
        return false
      end
    end
  end
end
