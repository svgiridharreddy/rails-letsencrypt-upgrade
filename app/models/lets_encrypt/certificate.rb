# frozen_string_literal: true

module LetsEncrypt
  # == Schema Information
  #
  # Table name: letsencrypt_certificates
  #
  #  id                  :integer          not null, primary key
  #  domain              :string(255)
  #  certificate         :text(65535)
  #  intermediaries      :text(65535)
  #  key                 :text(65535)
  #  expires_at          :datetime
  #  renew_after         :datetime
  #  verification_path   :string(255)
  #  verification_string :string(255)
  #  created_at          :datetime         not null
  #  updated_at          :datetime         not null
  #
  # Indexes
  #
  #  index_letsencrypt_certificates_on_domain       (domain)
  #  index_letsencrypt_certificates_on_renew_after  (renew_after)
  #
  class Certificate < ActiveRecord::Base
    include CertificateVerifiable
    include CertificateIssuable
    include CertificateStateMachineConcern

    validates :domain, presence: true, uniqueness: true

    scope :active, -> { where('certificate IS NOT NULL AND expires_at > ?', Time.zone.now) }
    scope :renewable, -> { where('renew_after IS NULL OR renew_after <= ?', Time.zone.now).where(status: statuses['state_issued']) }
    scope :expired, -> { where('expires_at <= ?', Time.zone.now) }

    before_create -> { self.key = OpenSSL::PKey::RSA.new(4096).to_s }
    after_save -> { save_to_redis }, if: -> { LetsEncrypt.config.use_redis? }

    # Returns true if certificate is expired.
    def expired?
      Time.zone.now >= expires_at
    end

    def active?
      self.state_issued? && !expired?
    end

    def verify!
      self.state_reset!
      save!
      if verify
        self.state_verify!
        true
      else
        logger.error "The certificate cannot be verified" 
        false
      end
    end

    def issue!
      if self.state_verified?
        if issue
          self.state_issue!
          return true
        else
          logger.error "The certificate cannot be issued"  
          return false
        end
      else
        logger.error "The certificate must be vertified before issued"
        return false
      end
    end

    # Returns true if success get a new certificate
    def get
      verify! && issue!
    end

    alias renew get

    # Returns full-chain bundled certificates
    def bundle
      [intermediaries, certificate].join("\n")
    end

    def certificate_object
      @certificate_object ||= OpenSSL::X509::Certificate.new(certificate)
    end

    def key_object
      @key_object ||= OpenSSL::PKey::RSA.new(key)
    end

    # Save certificate into redis
    def save_to_redis
      LetsEncrypt::Redis.save(self)
    end

    def all_domains
      [domain] + alternative_names
    end 

    protected

    def logger
      LetsEncrypt.logger
    end
  end
end
