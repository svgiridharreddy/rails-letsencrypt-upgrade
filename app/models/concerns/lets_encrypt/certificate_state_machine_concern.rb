module LetsEncrypt
  module CertificateStateMachineConcern

    extend ActiveSupport::Concern

    included do

      include AASM


      enum status: {
        state_unverified: 0, # the certificate created but not verified
        state_verified: 5, # the certificate is verified but not issued
        state_issued: 10, # the certificate is issued and not expired
        state_broken: 20, # the certificate is unable to be verified or issued anymore
      }

      aasm column: :status, enum: true, no_direct_assignment: true do

        state :state_unverified, initial: true
        state :state_verified
        state :state_issued
        state :state_broken

        event :state_reset do
          transitions to: :state_unverified
        end


        event :state_verify do
          transitions from: :state_unverified, to: :state_verified
        end

        event :state_issue do
          transitions from: :state_verified, to: :state_issued
        end

        event :mark_as_broken do
          transitions to: :state_broken
        end
      end
    end
  end
end
